import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { after, before, test } from "node:test";
import { ZodError } from "zod";

import { PDFDocument } from "pdf-lib";
import type pg from "pg";

import { exportEnvelopeAuditCsv } from "./audit-export.ts";
import { afterStatement, openTestDatabase } from "./db/test-database.ts";
import { ELECTRONIC_RECORDS_DISCLOSURE_VERSION } from "./electronic-records-disclosure.ts";
import {
  correctSentEnvelopeSigner,
  EnvelopeMutationError,
  getEnvelopeDetailDataForUser,
} from "./envelopes.ts";
import type { EnvelopeRecord } from "./schemas/envelope.ts";
import {
  duplicateSignerEmailMessage,
  type SignerRecord,
} from "./schemas/signer.ts";
import {
  listAuditEventsForEnvelope,
  recordAuditEvent,
  verifyAuditChain,
} from "./services/audit.ts";
import type {
  EmailService,
  TransactionalEmailMessage,
} from "./services/email.ts";
import { hashOpaqueToken } from "./services/opaque-tokens.ts";
import { renderEnvelopeCertificatePdf } from "./services/pdf-finalize.ts";
import { issueSigningLink } from "./services/signing-links.ts";
import {
  createStorageService,
  type StorageService,
} from "./services/storage.ts";
import {
  declineSigningForToken,
  getSigningPayloadForToken,
  recordSignerConsent,
  SigningAccessError,
  SigningMutationError,
  submitSigningForToken,
} from "./signing.ts";

// Correcting a waiting signer's name or email on a sent envelope, against
// a real Postgres. Run with `npm run test:db`.

process.env.APP_URL ??= "https://sign.example.test";

const DAY = 24 * 60 * 60;

let database: pg.Pool;
const createdUsers: string[] = [];

before(async () => {
  database = await openTestDatabase();
  globalThis.__signudocPgPool = database;
});

after(async () => {
  await database.query(`delete from public."user" where id = any($1)`, [
    createdUsers,
  ]);
  await database.end();
});

function unixNow() {
  return Math.floor(Date.now() / 1000);
}

function recordingEmailService(failWith?: Error) {
  const sent: TransactionalEmailMessage[] = [];
  const service: EmailService = {
    async send(message) {
      if (failWith) {
        throw failWith;
      }

      sent.push(message);

      return { accepted: [message.to], messageId: "m-1", rejected: [] };
    },
    async sendBatch() {
      throw new Error("not used");
    },
  };

  return { sent, service };
}

function deferred<T = void>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  const promise = new Promise<T>((next) => {
    resolve = next;
  });

  return { promise, resolve };
}

async function createOwner() {
  const userId = randomUUID();
  const email = `${userId}@example.test`;

  createdUsers.push(userId);
  await database.query(
    `insert into public."user" (id, name, email, role) values ($1, 'Sam Sender', $2, 'user')`,
    [userId, email],
  );

  return { email, userId };
}

async function createEnvelope({
  expiresAt = unixNow() + 30 * DAY,
  part11 = false,
  status = "sent",
  userId,
}: {
  expiresAt?: number | null;
  part11?: boolean;
  status?: "completed" | "declined" | "draft" | "sent" | "voided";
  userId: string;
}) {
  const envelopeId = randomUUID();
  const sentAt = status === "draft" ? null : unixNow() - 60;

  await database.query(
    `
      insert into envelopes (
        id, user_id, title, status, source_pdf_key, source_pdf_filename,
        source_pdf_size_bytes, page_count, source_pdf_hash, sent_at,
        expires_at, part11, completed_at, declined_at, voided_at
      ) values (
        $1, $2, 'Lease', $3, $4, 'lease.pdf', 10, 1, $5, $6, $7, $8,
        $9, $10, $11
      )
    `,
    [
      envelopeId,
      userId,
      status,
      `test/${envelopeId}.pdf`,
      "a".repeat(64),
      sentAt,
      status === "draft" ? null : expiresAt,
      part11,
      status === "completed" ? unixNow() : null,
      status === "declined" ? unixNow() : null,
      status === "voided" ? unixNow() : null,
    ],
  );

  return envelopeId;
}

async function createSigner({
  email,
  envelopeId,
  extra,
  name = "Riley Recipient",
  signOrder = 1,
  status = "notified",
}: {
  email?: string;
  envelopeId: string;
  extra?: {
    consentedAt?: number | null;
    emailCodeAttempts?: number;
    emailCodeExpiresAt?: number | null;
    emailCodeHash?: string | null;
    emailCodeSentAt?: number | null;
  };
  name?: string;
  signOrder?: number;
  status?: "declined" | "notified" | "pending" | "signed";
}) {
  const signerId = randomUUID();
  const link =
    status === "notified"
      ? await issueSigningLink({ expiresInSeconds: 30 * DAY })
      : null;

  await database.query(
    `
      insert into signers (
        id, envelope_id, name, email, sign_order, status,
        signing_token_hash, signing_token_expires_at, last_notified_at,
        signed_at, declined_at, email_code_hash, email_code_expires_at,
        email_code_attempts, email_code_sent_at, consented_at
      ) values (
        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16
      )
    `,
    [
      signerId,
      envelopeId,
      name,
      email ?? `${signerId}@example.test`,
      signOrder,
      status,
      link?.tokenHash ?? null,
      link?.exp ?? null,
      status === "notified" ? unixNow() : null,
      status === "signed" ? unixNow() : null,
      status === "declined" ? unixNow() : null,
      extra?.emailCodeHash ?? null,
      extra?.emailCodeExpiresAt ?? null,
      extra?.emailCodeAttempts ?? 0,
      extra?.emailCodeSentAt ?? null,
      extra?.consentedAt ?? null,
    ],
  );

  return {
    email: email ?? `${signerId}@example.test`,
    signerId,
    token: link?.token ?? null,
    tokenHash: link?.tokenHash ?? null,
  };
}

async function readSigner(signerId: string) {
  const result = await database.query<{
    consented_at: number | null;
    email: string;
    email_code_attempts: number;
    email_code_hash: string | null;
    email_code_sent_at: number | null;
    name: string;
    signing_token_hash: string | null;
    status: string;
  }>(
    `
      select
        consented_at, email, email_code_attempts, email_code_hash,
        email_code_sent_at, name, signing_token_hash, status
      from signers
      where id = $1
    `,
    [signerId],
  );

  return result.rows[0]!;
}

async function auditEvents(envelopeId: string) {
  const result = await database.query<{ event: string }>(
    `select event from audit_events where envelope_id = $1 order by sequence`,
    [envelopeId],
  );

  return result.rows.map((row) => row.event);
}

function correct(
  userId: string,
  envelopeId: string,
  signerId: string,
  body: unknown,
  emailService?: EmailService,
) {
  return correctSentEnvelopeSigner(
    userId,
    envelopeId,
    signerId,
    body,
    {
      ipAddress: "203.0.113.8",
      senderEmail: "sam@example.test",
      senderName: "Sam Sender",
      userAgent: "test",
    },
    { database, emailService },
  );
}

const DRAWN_SIGNATURE =
  "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==";

function stubStorage(putObject?: StorageService["putObject"]): StorageService {
  const refuse = async (): Promise<never> => {
    throw new Error("not used");
  };

  return {
    deleteObject: async () => undefined,
    getObject: refuse,
    getObjectStream: refuse,
    headObject: refuse,
    putObject: putObject ?? (async ({ key }) => ({ bucketName: "test", key })),
  };
}

async function addSignatureField(envelopeId: string, signerId: string) {
  const fieldId = randomUUID();

  await database.query(
    `
      insert into fields (
        id, envelope_id, signer_id, type, page, x, y, width, height
      ) values ($1, $2, $3, 'signature', 1, 0.1, 0.1, 0.2, 0.1)
    `,
    [fieldId, envelopeId, signerId],
  );

  return fieldId;
}

function consent(token: string) {
  return recordSignerConsent(
    token,
    { disclosureVersion: ELECTRONIC_RECORDS_DISCLOSURE_VERSION },
    { database },
  );
}

function submitDrawn(
  token: string,
  fieldId: string,
  {
    emailService = recordingEmailService().service,
    storageService = stubStorage(),
  }: {
    emailService?: EmailService;
    storageService?: StorageService;
  } = {},
) {
  return submitSigningForToken(
    token,
    {
      clientTimezoneOffsetMinutes: 0,
      fields: [
        {
          fieldId,
          imageDataUrl: DRAWN_SIGNATURE,
          inputMethod: "drawn",
          type: "signature",
        },
      ],
    },
    { database, emailService, storageService },
  );
}

async function extractPdfText(pdfBytes: Uint8Array): Promise<string> {
  const pdfjs = await import("pdfjs-dist/legacy/build/pdf.mjs");
  const document = await pdfjs.getDocument({
    data: new Uint8Array(pdfBytes),
    useSystemFonts: false,
    verbosity: 0,
  }).promise;
  const parts: string[] = [];

  for (let pageNumber = 1; pageNumber <= document.numPages; pageNumber += 1) {
    const page = await document.getPage(pageNumber);
    const content = await page.getTextContent();

    parts.push(
      content.items.map((item: { str?: string }) => item.str ?? "").join(" "),
    );
  }

  await document.destroy();

  return parts.join("\n").replace(/\s+/g, " ");
}

async function renderCorrectionCertificates(envelopeId: string) {
  const envelopeRow = await database.query<{
    created_at: number;
    source_pdf_filename: string;
    source_pdf_hash: string;
    source_pdf_key: string;
    source_pdf_size_bytes: number;
    title: string;
    updated_at: number;
    user_id: string;
  }>(
    `
      select created_at, source_pdf_filename, source_pdf_hash, source_pdf_key,
             source_pdf_size_bytes, title, updated_at, user_id
      from envelopes
      where id = $1
    `,
    [envelopeId],
  );
  const row = envelopeRow.rows[0]!;
  const now = unixNow();
  const envelope: EnvelopeRecord = {
    completedAt: now,
    createdAt: row.created_at,
    declinedAt: null,
    evidenceKey: null,
    id: envelopeId,
    pageCount: 1,
    sentAt: now - 60,
    signedPdfKey: null,
    sourcePdfFilename: row.source_pdf_filename,
    sourcePdfHash: row.source_pdf_hash,
    sourcePdfKey: row.source_pdf_key,
    sourcePdfSizeBytes: row.source_pdf_size_bytes,
    status: "completed",
    title: row.title,
    updatedAt: row.updated_at,
    userId: row.user_id,
    voidedAt: null,
  };
  const signerRows = await database.query<{
    created_at: number;
    email: string;
    id: string;
    name: string;
    sign_order: number;
    signed_at: number | null;
    status: SignerRecord["status"];
    updated_at: number;
  }>(
    `
      select created_at, email, id, name, sign_order, signed_at, status, updated_at
      from signers
      where envelope_id = $1 and role = 'signer'
      order by sign_order
    `,
    [envelopeId],
  );
  const signers: SignerRecord[] = signerRows.rows.map((signer) => ({
    createdAt: signer.created_at,
    email: signer.email,
    id: signer.id,
    name: signer.name,
    signedAt: signer.signed_at,
    signOrder: signer.sign_order,
    status: signer.status === "notified" ? "signed" : signer.status,
    updatedAt: signer.updated_at,
  }));
  const auditEvents = await listAuditEventsForEnvelope(envelopeId, database);
  const seal = (pdfDocument: PDFDocument) => pdfDocument.save();
  const full = await renderEnvelopeCertificatePdf(
    { auditEvents, envelope, signers },
    { seal },
  );
  const redacted = await renderEnvelopeCertificatePdf(
    { auditEvents, envelope, redactForRecipients: true, signers },
    { seal },
  );

  return {
    full: await extractPdfText(full),
    redacted: await extractPdfText(redacted),
  };
}

test("correcting a notified signer rotates the link and emails the new address", async () => {
  const { userId } = await createOwner();
  const envelopeId = await createEnvelope({ userId });
  const signer = await createSigner({
    envelopeId,
    extra: {
      consentedAt: unixNow() - 10,
      emailCodeAttempts: 2,
      emailCodeExpiresAt: unixNow() + 600,
      emailCodeHash: "a".repeat(64),
      emailCodeSentAt: unixNow() - 30,
    },
  });
  const { sent, service } = recordingEmailService();
  const oldToken = signer.token!;

  const result = await correct(
    userId,
    envelopeId,
    signer.signerId,
    { email: "riley.fixed@example.test", name: "Riley Recipient" },
    service,
  );

  assert.equal(result.invitationSent, true);
  assert.equal(result.email, "riley.fixed@example.test");
  const stored = await readSigner(signer.signerId);
  assert.equal(stored.email, "riley.fixed@example.test");
  assert.notEqual(stored.signing_token_hash, signer.tokenHash);
  assert.equal(stored.consented_at, null);
  assert.equal(stored.email_code_hash, null);
  assert.equal(stored.email_code_attempts, 0);
  assert.equal(stored.email_code_sent_at, null);

  await assert.rejects(getSigningPayloadForToken(oldToken, { database }), {
    message: "This link has expired.",
    name: "SigningAccessError",
  });
  await assert.rejects(
    getSigningPayloadForToken(oldToken, { database }),
    (error: unknown) => {
      assert.ok(error instanceof SigningAccessError);
      assert.equal(error.state, "expired");
      return true;
    },
  );

  assert.equal(sent.length, 1);
  assert.equal(sent[0]?.to, "riley.fixed@example.test");
  assert.equal(sent[0]?.template, "signing_invitation");
  const match = sent[0]?.textBody.match(/\/sign\/([A-Za-z0-9_-]+)/);
  assert.ok(match?.[1]);
  assert.equal(stored.signing_token_hash, hashOpaqueToken(match[1]!));

  assert.deepEqual(await auditEvents(envelopeId), [
    "signer_corrected",
    "email_sent",
  ]);
  assert.equal((await verifyAuditChain(envelopeId, database)).ok, true);

  const detail = await getEnvelopeDetailDataForUser(
    userId,
    envelopeId,
    database,
  );
  assert.ok(
    detail?.timeline.some((item) =>
      item.description.includes(
        "Signer email corrected from " +
          `${signer.email} to riley.fixed@example.test`,
      ),
    ),
  );

  const csv = await exportEnvelopeAuditCsv(userId, envelopeId, database);
  assert.match(csv.body, /Signer corrected/);
  assert.match(
    csv.body,
    /Signer email corrected from .* to riley\.fixed@example\.test/,
  );
});

test("correcting a pending signer records the change and sends no invitation", async () => {
  const { userId } = await createOwner();
  const envelopeId = await createEnvelope({ userId });
  await createSigner({ envelopeId, signOrder: 1, status: "notified" });
  const pending = await createSigner({
    envelopeId,
    name: "Casey Second",
    signOrder: 2,
    status: "pending",
  });
  const { sent, service } = recordingEmailService();

  const result = await correct(
    userId,
    envelopeId,
    pending.signerId,
    { email: "casey.fixed@example.test" },
    service,
  );

  assert.equal(result.invitationSent, false);
  assert.equal(sent.length, 0);
  assert.equal(
    (await readSigner(pending.signerId)).email,
    "casey.fixed@example.test",
  );
  assert.deepEqual(await auditEvents(envelopeId), ["signer_corrected"]);
  assert.equal((await verifyAuditChain(envelopeId, database)).ok, true);
});

test("the same name and email is a no-op: the link stays and nothing is audited", async () => {
  const { userId } = await createOwner();
  const envelopeId = await createEnvelope({ userId });
  const signer = await createSigner({
    email: "riley@example.test",
    envelopeId,
    name: "Riley Recipient",
  });
  const { sent, service } = recordingEmailService();

  const result = await correct(
    userId,
    envelopeId,
    signer.signerId,
    { email: "Riley@Example.TEST", name: "Riley Recipient" },
    service,
  );

  assert.equal(result.invitationSent, false);
  assert.equal(result.email, "riley@example.test");
  assert.equal(
    (await readSigner(signer.signerId)).signing_token_hash,
    signer.tokenHash,
  );
  assert.equal(sent.length, 0);
  assert.deepEqual(await auditEvents(envelopeId), []);
  const stillLinked = await database.query<{ id: string }>(
    `select id from signers where signing_token_hash = $1`,
    [hashOpaqueToken(signer.token!)],
  );
  assert.equal(stillLinked.rows[0]?.id, signer.signerId);
});

test("a passed deadline can still have a signer corrected", async () => {
  const { userId } = await createOwner();
  const envelopeId = await createEnvelope({
    expiresAt: unixNow() - 60,
    userId,
  });
  const signer = await createSigner({ envelopeId });
  const { sent, service } = recordingEmailService();

  const result = await correct(
    userId,
    envelopeId,
    signer.signerId,
    { name: "Riley Fixed" },
    service,
  );

  assert.equal(result.invitationSent, true);
  assert.equal(sent.length, 1);
  assert.notEqual(
    (await readSigner(signer.signerId)).signing_token_hash,
    signer.tokenHash,
  );
  await assert.rejects(getSigningPayloadForToken(signer.token!, { database }), {
    name: "SigningAccessError",
  });
});

test("another signer's email is refused", async () => {
  const { userId } = await createOwner();
  const envelopeId = await createEnvelope({ userId });
  const first = await createSigner({
    email: "riley@example.test",
    envelopeId,
  });
  const second = await createSigner({
    email: "casey@example.test",
    envelopeId,
    name: "Casey Second",
    signOrder: 2,
    status: "pending",
  });

  await assert.rejects(
    correct(userId, envelopeId, second.signerId, {
      email: "riley@example.test",
    }),
    (error: unknown) => {
      assert.ok(error instanceof EnvelopeMutationError);
      assert.equal(error.statusCode, 400);
      assert.equal(error.message, duplicateSignerEmailMessage);
      return true;
    },
  );
  assert.equal((await readSigner(first.signerId)).email, "riley@example.test");
});

test("a signed or declined signer cannot be corrected", async () => {
  const { userId } = await createOwner();
  const envelopeId = await createEnvelope({ userId });
  const signed = await createSigner({
    envelopeId,
    status: "signed",
  });
  const declined = await createSigner({
    envelopeId,
    name: "Casey Second",
    signOrder: 2,
    status: "declined",
  });

  await assert.rejects(
    correct(userId, envelopeId, signed.signerId, { name: "Nope" }),
    (error: unknown) => {
      assert.ok(error instanceof EnvelopeMutationError);
      assert.equal(error.statusCode, 409);
      assert.match(error.message, /already signed/);
      return true;
    },
  );
  await assert.rejects(
    correct(userId, envelopeId, declined.signerId, { name: "Nope" }),
    (error: unknown) => {
      assert.ok(error instanceof EnvelopeMutationError);
      assert.equal(error.statusCode, 409);
      assert.match(error.message, /already declined/);
      return true;
    },
  );
});

test("a copy recipient cannot be corrected here", async () => {
  const { userId } = await createOwner();
  const envelopeId = await createEnvelope({ userId });
  await createSigner({ envelopeId });
  const copyId = randomUUID();
  await database.query(
    `
      insert into signers (
        id, envelope_id, name, email, sign_order, status, role
      ) values ($1, $2, 'Zofia Copy', 'zofia@example.test', 501, 'pending', 'cc')
    `,
    [copyId, envelopeId],
  );

  await assert.rejects(
    correct(userId, envelopeId, copyId, { email: "zofia.fixed@example.test" }),
    (error: unknown) => {
      assert.ok(error instanceof EnvelopeMutationError);
      assert.equal(error.statusCode, 404);
      return true;
    },
  );
});

test("draft, completed, declined and voided envelopes are refused", async () => {
  const { userId } = await createOwner();

  for (const status of ["draft", "completed", "declined", "voided"] as const) {
    const envelopeId = await createEnvelope({ status, userId });
    const signer = await createSigner({
      envelopeId,
      status: status === "draft" ? "pending" : "notified",
    });

    await assert.rejects(
      correct(userId, envelopeId, signer.signerId, { name: "Nope" }),
      (error: unknown) => {
        assert.ok(error instanceof EnvelopeMutationError);
        assert.equal(error.statusCode, 409);
        assert.match(error.message, /out for signature/);
        return true;
      },
    );
  }
});

test("a Part 11 envelope cannot have a signer corrected", async () => {
  const { userId } = await createOwner();
  const envelopeId = await createEnvelope({ part11: true, userId });
  const signer = await createSigner({ envelopeId });

  await assert.rejects(
    correct(userId, envelopeId, signer.signerId, {
      email: "riley.fixed@example.test",
    }),
    (error: unknown) => {
      assert.ok(error instanceof EnvelopeMutationError);
      assert.equal(error.statusCode, 409);
      assert.match(error.message, /Part 11/);
      return true;
    },
  );
});

test("another user cannot correct a signer", async () => {
  const owner = await createOwner();
  const other = await createOwner();
  const envelopeId = await createEnvelope({ userId: owner.userId });
  const signer = await createSigner({ envelopeId });

  await assert.rejects(
    correct(other.userId, envelopeId, signer.signerId, { name: "Nope" }),
    (error: unknown) => {
      assert.ok(error instanceof EnvelopeMutationError);
      assert.equal(error.statusCode, 404);
      return true;
    },
  );
});

test("an empty or invalid correction is refused by the schema", async () => {
  const { userId } = await createOwner();
  const envelopeId = await createEnvelope({ userId });
  const signer = await createSigner({ envelopeId });

  await assert.rejects(
    correct(userId, envelopeId, signer.signerId, {}),
    ZodError,
  );
  await assert.rejects(
    correct(userId, envelopeId, signer.signerId, { email: "not-an-email" }),
    ZodError,
  );
});

test("a failed invitation leaves the old name, email and link in place", async () => {
  const { userId } = await createOwner();
  const envelopeId = await createEnvelope({ userId });
  const signer = await createSigner({ envelopeId });
  const { service } = recordingEmailService(new Error("mailbox down"));

  await assert.rejects(
    correct(
      userId,
      envelopeId,
      signer.signerId,
      { email: "riley.fixed@example.test" },
      service,
    ),
    { message: "mailbox down" },
  );

  const stored = await readSigner(signer.signerId);
  assert.equal(stored.email, signer.email);
  assert.equal(stored.signing_token_hash, signer.tokenHash);
  assert.deepEqual(await auditEvents(envelopeId), []);
});

test("recipient certificates omit a correction's previous email", async () => {
  const { userId } = await createOwner();
  const envelopeId = await createEnvelope({ userId });
  const previousEmail = `previous.${randomUUID()}@hide.test`;
  const signer = await createSigner({
    email: previousEmail,
    envelopeId,
  });
  const { service } = recordingEmailService();

  await correct(
    userId,
    envelopeId,
    signer.signerId,
    { email: "riley.fixed@example.test" },
    service,
  );

  const { full, redacted } = await renderCorrectionCertificates(envelopeId);

  assert.ok(full.includes(previousEmail));
  assert.ok(full.includes("Signer email corrected from"));
  assert.ok(!redacted.includes(previousEmail));
  assert.ok(redacted.includes("Signer email was corrected"));
});

test("the certificate credits consent recorded after a signer correction", async () => {
  const { userId } = await createOwner();
  const envelopeId = await createEnvelope({ userId });
  const oldConsentAt = unixNow() - 3_600;
  const signer = await createSigner({
    envelopeId,
    extra: { consentedAt: oldConsentAt },
  });

  await recordAuditEvent(
    {
      actorEmail: signer.email,
      actorType: "signer",
      createdAt: oldConsentAt,
      envelopeId,
      event: "consented",
      metadata: {
        disclosureVersion: "old-version",
        signerId: signer.signerId,
        signerName: "Riley Recipient",
      },
    },
    database,
  );

  const { sent, service } = recordingEmailService();

  await correct(
    userId,
    envelopeId,
    signer.signerId,
    { email: "riley.fixed@example.test" },
    service,
  );

  const match = sent[0]?.textBody.match(/\/sign\/([A-Za-z0-9_-]+)/);
  assert.ok(match?.[1]);
  await consent(match[1]!);

  const { full } = await renderCorrectionCertificates(envelopeId);
  const signersSection = (full.split("Audit events")[0] ?? "").replace(
    /\s+/g,
    " ",
  );
  const compactSigners = signersSection.replaceAll(" ", "");

  assert.ok(
    compactSigners.includes(
      `disclosure${ELECTRONIC_RECORDS_DISCLOSURE_VERSION}`,
    ),
    signersSection,
  );
  assert.ok(!compactSigners.includes("disclosureold-version"));
});

test("an in-flight submit on the old link cannot finish after a correction", async () => {
  const { userId } = await createOwner();
  const envelopeId = await createEnvelope({ userId });
  const first = await createSigner({ envelopeId });
  await createSigner({
    envelopeId,
    name: "Casey Second",
    signOrder: 2,
    status: "pending",
  });
  const fieldId = await addSignatureField(envelopeId, first.signerId);
  await consent(first.token!);
  const { service } = recordingEmailService();
  const storageService = stubStorage(async ({ key }) => {
    await correct(
      userId,
      envelopeId,
      first.signerId,
      { email: "riley.fixed@example.test" },
      service,
    );

    return { bucketName: "test", key };
  });

  await assert.rejects(
    submitDrawn(first.token!, fieldId, { storageService }),
    (error: unknown) => {
      assert.ok(error instanceof SigningMutationError);
      assert.equal(error.statusCode, 409);
      return true;
    },
  );

  const stored = await readSigner(first.signerId);
  assert.equal(stored.status, "notified");
  assert.equal(stored.email, "riley.fixed@example.test");
  assert.notEqual(stored.signing_token_hash, first.tokenHash);
});

test("an in-flight consent on the old link cannot finish after a correction", async () => {
  const { userId } = await createOwner();
  const envelopeId = await createEnvelope({ userId });
  const signer = await createSigner({ envelopeId });
  const { service } = recordingEmailService();
  const pool = afterStatement(
    database,
    (text) => text.includes('access_code_hash AS "accessCodeHash"'),
    async () => {
      await correct(
        userId,
        envelopeId,
        signer.signerId,
        { email: "riley.fixed@example.test" },
        service,
      );
    },
  );

  await assert.rejects(
    recordSignerConsent(
      signer.token!,
      { disclosureVersion: ELECTRONIC_RECORDS_DISCLOSURE_VERSION },
      { database: pool },
    ),
    (error: unknown) => {
      assert.ok(error instanceof SigningMutationError);
      assert.equal(error.statusCode, 409);
      return true;
    },
  );

  assert.equal((await readSigner(signer.signerId)).consented_at, null);
});

test("an in-flight decline on the old link cannot finish after a correction", async () => {
  const { userId } = await createOwner();
  const envelopeId = await createEnvelope({ userId });
  const signer = await createSigner({ envelopeId });
  const storageDir = await mkdtemp(
    path.join(tmpdir(), "signudoc-correct-decline-"),
  );
  const storageService = createStorageService({
    env: { STORAGE_DRIVER: "local", STORAGE_LOCAL_DIR: storageDir },
  });
  const sourcePdf = await PDFDocument.create();

  sourcePdf.addPage([612, 792]);

  const sourcePdfBytes = await sourcePdf.save();

  await storageService.putObject({
    body: sourcePdfBytes,
    contentType: "application/pdf",
    key: `test/${envelopeId}.pdf`,
  });
  await database.query(
    `
      insert into envelope_pages (id, envelope_id, page_number, width_pt, height_pt)
      values ($1, $2, 1, 612, 792)
    `,
    [randomUUID(), envelopeId],
  );
  await consent(signer.token!);

  const { service } = recordingEmailService();
  const settings = {
    EMAIL_CAPTURE_DIR: path.join(storageDir, "outbox"),
    EMAIL_DRIVER: "capture",
    STORAGE_DRIVER: "local",
    STORAGE_LOCAL_DIR: storageDir,
  };
  const settingsBefore = Object.keys(settings).map(
    (name) => [name, process.env[name]] as const,
  );

  Object.assign(process.env, settings);

  const pool = afterStatement(
    database,
    (text) => text.includes('access_code_hash AS "accessCodeHash"'),
    async () => {
      await correct(
        userId,
        envelopeId,
        signer.signerId,
        { email: "riley.fixed@example.test" },
        service,
      );
    },
  );

  try {
    await assert.rejects(
      declineSigningForToken(
        signer.token!,
        { reason: "Changed mind." },
        {
          database: pool,
        },
      ),
      (error: unknown) => {
        assert.ok(error instanceof SigningMutationError);
        assert.equal(error.statusCode, 409);
        return true;
      },
    );
    assert.equal((await readSigner(signer.signerId)).status, "notified");
  } finally {
    for (const [name, value] of settingsBefore) {
      if (value === undefined) {
        delete process.env[name];
      } else {
        process.env[name] = value;
      }
    }

    await rm(storageDir, { force: true, recursive: true });
  }
});

test("activating the next signer emails the address stored under the lock", async () => {
  const { userId } = await createOwner();
  const envelopeId = await createEnvelope({ userId });
  const first = await createSigner({ envelopeId });
  const pending = await createSigner({
    email: "casey.typo@example.test",
    envelopeId,
    name: "Casey Second",
    signOrder: 2,
    status: "pending",
  });
  const fieldId = await addSignatureField(envelopeId, first.signerId);
  await consent(first.token!);
  const { sent, service } = recordingEmailService();
  const storageService = stubStorage(async ({ key }) => {
    await correct(
      userId,
      envelopeId,
      pending.signerId,
      { email: "casey.fixed@example.test" },
      service,
    );

    return { bucketName: "test", key };
  });

  await submitDrawn(first.token!, fieldId, {
    emailService: service,
    storageService,
  });

  const invitation = sent.find(
    (message) => message.template === "signing_invitation",
  );

  assert.equal(invitation?.to, "casey.fixed@example.test");
  assert.equal(
    (await readSigner(pending.signerId)).email,
    "casey.fixed@example.test",
  );
  assert.equal((await readSigner(pending.signerId)).status, "notified");
  assert.ok(!sent.some((message) => message.to === "casey.typo@example.test"));
});

test("a failed invitation does not undo a later correction of the same signer", async () => {
  const { userId } = await createOwner();
  const envelopeId = await createEnvelope({ userId });
  const signer = await createSigner({ envelopeId });
  const { sent: sentB, service: serviceB } = recordingEmailService();
  const { service: serviceA } = recordingEmailService(
    new Error("mailbox down"),
  );

  const outcomes = await Promise.allSettled([
    correct(
      userId,
      envelopeId,
      signer.signerId,
      { email: "first@example.test" },
      serviceA,
    ),
    correct(
      userId,
      envelopeId,
      signer.signerId,
      { email: "second@example.test" },
      serviceB,
    ),
  ]);

  assert.equal(
    outcomes.filter((outcome) => outcome.status === "fulfilled").length,
    1,
  );
  assert.equal(
    outcomes.filter((outcome) => outcome.status === "rejected").length,
    1,
  );

  const stored = await readSigner(signer.signerId);
  assert.equal(stored.email, "second@example.test");
  assert.notEqual(stored.signing_token_hash, signer.tokenHash);
  assert.equal(sentB.length, 1);
  assert.equal(sentB[0]?.to, "second@example.test");
  await assert.rejects(getSigningPayloadForToken(signer.token!, { database }), {
    name: "SigningAccessError",
  });
  assert.deepEqual(await auditEvents(envelopeId), [
    "signer_corrected",
    "email_sent",
  ]);
  assert.equal((await verifyAuditChain(envelopeId, database)).ok, true);
  const csv = await exportEnvelopeAuditCsv(userId, envelopeId, database);
  assert.equal((csv.body.match(/Signer corrected/g) ?? []).length, 1);
  assert.match(
    csv.body,
    new RegExp(
      `Signer email corrected from ${signer.email.replaceAll(".", "\\.")} to second@example\\.test`,
    ),
  );
});

test("two overlapping failed invitations restore the original signer and link", async () => {
  const { userId } = await createOwner();
  const envelopeId = await createEnvelope({ userId });
  const signer = await createSigner({
    envelopeId,
    extra: { consentedAt: unixNow() - 20 },
  });
  const originalConsentedAt = (await readSigner(signer.signerId)).consented_at;
  const { service: serviceA } = recordingEmailService(
    new Error("mailbox down"),
  );
  const { service: serviceB } = recordingEmailService(
    new Error("mailbox down"),
  );

  const outcomes = await Promise.allSettled([
    correct(
      userId,
      envelopeId,
      signer.signerId,
      { email: "first@example.test" },
      serviceA,
    ),
    correct(
      userId,
      envelopeId,
      signer.signerId,
      { email: "second@example.test" },
      serviceB,
    ),
  ]);

  assert.equal(
    outcomes.filter((outcome) => outcome.status === "rejected").length,
    2,
  );

  const stored = await readSigner(signer.signerId);
  assert.equal(stored.email, signer.email);
  assert.equal(stored.signing_token_hash, signer.tokenHash);
  assert.equal(stored.consented_at, originalConsentedAt);
  assert.deepEqual(await auditEvents(envelopeId), []);
  await getSigningPayloadForToken(signer.token!, { database });
});

test("overlapping successful corrections record audit events in save order", async () => {
  const { userId } = await createOwner();
  const envelopeId = await createEnvelope({ userId });
  const signer = await createSigner({ envelopeId });
  const firstStarted = deferred();
  const firstMayFinish = deferred();
  const sentFirst: TransactionalEmailMessage[] = [];
  const { sent: sentSecond, service: serviceSecond } = recordingEmailService();
  const serviceFirst: EmailService = {
    async send(message) {
      firstStarted.resolve();
      await firstMayFinish.promise;
      sentFirst.push(message);

      return { accepted: [message.to], messageId: "m-first", rejected: [] };
    },
    async sendBatch() {
      throw new Error("not used");
    },
  };

  const firstCorrection = correct(
    userId,
    envelopeId,
    signer.signerId,
    { email: "first@example.test" },
    serviceFirst,
  );
  await firstStarted.promise;

  const secondCorrection = correct(
    userId,
    envelopeId,
    signer.signerId,
    { email: "second@example.test" },
    serviceSecond,
  );

  await new Promise((resolve) => setTimeout(resolve, 50));
  assert.equal(sentSecond.length, 0);
  assert.equal((await readSigner(signer.signerId)).email, signer.email);

  firstMayFinish.resolve();
  await Promise.all([firstCorrection, secondCorrection]);

  const stored = await readSigner(signer.signerId);
  assert.equal(stored.email, "second@example.test");
  assert.equal(sentFirst.length, 1);
  assert.equal(sentSecond.length, 1);
  assert.deepEqual(await auditEvents(envelopeId), [
    "signer_corrected",
    "email_sent",
    "signer_corrected",
    "email_sent",
  ]);

  const recorded = await listAuditEventsForEnvelope(envelopeId, database);
  const corrections = recorded.filter(
    (event) => event.event === "signer_corrected",
  );
  assert.equal(corrections[0]?.metadata?.signerEmail, "first@example.test");
  assert.equal(corrections[0]?.metadata?.previousEmail, signer.email);
  assert.equal(corrections[1]?.metadata?.signerEmail, "second@example.test");
  assert.equal(corrections[1]?.metadata?.previousEmail, "first@example.test");
  assert.equal((await verifyAuditChain(envelopeId, database)).ok, true);

  const match = sentSecond[0]?.textBody.match(/\/sign\/([A-Za-z0-9_-]+)/);
  assert.ok(match?.[1]);
  await consent(match[1]!);

  const { full } = await renderCorrectionCertificates(envelopeId);
  const signersSection = (full.split("Audit events")[0] ?? "").replace(
    /\s+/g,
    " ",
  );
  const compactSigners = signersSection.replaceAll(" ", "");

  assert.ok(
    compactSigners.includes(
      `disclosure${ELECTRONIC_RECORDS_DISCLOSURE_VERSION}`,
    ),
    signersSection,
  );
});

test("a failed invitation leaves no correction in the audit trail when a later event is recorded", async () => {
  const { userId } = await createOwner();
  const envelopeId = await createEnvelope({ userId });
  const signer = await createSigner({ envelopeId });
  const service: EmailService = {
    async send() {
      await recordAuditEvent(
        {
          actorEmail: signer.email,
          actorType: "signer",
          envelopeId,
          event: "viewed",
          metadata: { signerId: signer.signerId },
        },
        database,
      );
      throw new Error("mailbox down");
    },
    async sendBatch() {
      throw new Error("not used");
    },
  };

  await assert.rejects(
    correct(
      userId,
      envelopeId,
      signer.signerId,
      { email: "riley.fixed@example.test" },
      service,
    ),
    { message: "mailbox down" },
  );

  const stored = await readSigner(signer.signerId);
  assert.equal(stored.email, signer.email);
  assert.equal(stored.signing_token_hash, signer.tokenHash);
  assert.deepEqual(await auditEvents(envelopeId), ["viewed"]);
  assert.equal((await verifyAuditChain(envelopeId, database)).ok, true);

  const csv = await exportEnvelopeAuditCsv(userId, envelopeId, database);
  assert.doesNotMatch(csv.body, /Signer corrected/);
  assert.doesNotMatch(csv.body, /riley\.fixed@example\.test/);
});

test("a failed invitation restores consent and keeps it on the certificate", async () => {
  const { userId } = await createOwner();
  const envelopeId = await createEnvelope({ userId });
  const consentedAt = unixNow() - 60;
  const signer = await createSigner({
    envelopeId,
    extra: { consentedAt },
  });

  await recordAuditEvent(
    {
      actorEmail: signer.email,
      actorType: "signer",
      createdAt: consentedAt,
      envelopeId,
      event: "consented",
      metadata: {
        disclosureVersion: "kept-version",
        signerId: signer.signerId,
        signerName: "Riley Recipient",
      },
    },
    database,
  );

  const service: EmailService = {
    async send() {
      await recordAuditEvent(
        {
          actorEmail: "riley.fixed@example.test",
          actorType: "signer",
          envelopeId,
          event: "viewed",
          metadata: { signerId: signer.signerId },
        },
        database,
      );
      throw new Error("mailbox down");
    },
    async sendBatch() {
      throw new Error("not used");
    },
  };

  await assert.rejects(
    correct(
      userId,
      envelopeId,
      signer.signerId,
      { email: "riley.fixed@example.test" },
      service,
    ),
    { message: "mailbox down" },
  );

  const stored = await readSigner(signer.signerId);
  assert.equal(stored.email, signer.email);
  assert.equal(stored.consented_at, consentedAt);
  assert.deepEqual(await auditEvents(envelopeId), ["consented", "viewed"]);

  const { full } = await renderCorrectionCertificates(envelopeId);
  const signersSection = (full.split("Audit events")[0] ?? "").replace(
    /\s+/g,
    " ",
  );
  const compactSigners = signersSection.replaceAll(" ", "");

  assert.ok(compactSigners.includes("disclosurekept-version"), signersSection);
});

test("a missing email configuration rolls the correction back", async () => {
  const { userId } = await createOwner();
  const envelopeId = await createEnvelope({ userId });
  const consentedAt = unixNow() - 10;
  const signer = await createSigner({
    envelopeId,
    extra: { consentedAt },
  });
  const previous = {
    EMAIL_DRIVER: process.env.EMAIL_DRIVER,
    RESEND_API_KEY: process.env.RESEND_API_KEY,
  };

  process.env.EMAIL_DRIVER = "resend";
  delete process.env.RESEND_API_KEY;

  try {
    await assert.rejects(
      correct(userId, envelopeId, signer.signerId, {
        email: "riley.fixed@example.test",
      }),
      (error: unknown) => {
        assert.ok(error instanceof Error);
        assert.match(error.message, /RESEND_API_KEY/);
        return true;
      },
    );
  } finally {
    if (previous.EMAIL_DRIVER === undefined) {
      delete process.env.EMAIL_DRIVER;
    } else {
      process.env.EMAIL_DRIVER = previous.EMAIL_DRIVER;
    }

    if (previous.RESEND_API_KEY === undefined) {
      delete process.env.RESEND_API_KEY;
    } else {
      process.env.RESEND_API_KEY = previous.RESEND_API_KEY;
    }
  }

  const stored = await readSigner(signer.signerId);
  assert.equal(stored.email, signer.email);
  assert.equal(stored.signing_token_hash, signer.tokenHash);
  assert.equal(stored.consented_at, consentedAt);
  assert.deepEqual(await auditEvents(envelopeId), []);
});

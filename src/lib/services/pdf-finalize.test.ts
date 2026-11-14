import assert from "node:assert/strict";
import test from "node:test";

import { PDFDocument } from "pdf-lib";

import type { AuditEventRecord, EnvelopeRecord } from "../schemas/envelope.ts";
import type { FieldRecord } from "../schemas/field.ts";
import type { SignerRecord } from "../schemas/signer.ts";
import {
  renderEnvelopeCertificatePdf,
  renderFinalizedEnvelopePdf,
} from "./pdf-finalize.ts";
import { sha256Hex } from "./pdf-seal.ts";
import type { StorageService } from "./storage.ts";

// Names and values outside Windows-1252 used to fail the whole signing with
// "WinAnsi cannot encode". These tests run the two renderers on such text.

const TITLE = "Umowa o dzieło – Łódź / 業務委託契約書";
const SIGNER_NAME = "Łukasz Żółć";
const SECOND_SIGNER_NAME = "山田 太郎";
const TEXT_VALUE = "Санкт-Петербург, 東京都";

async function extractText(pdfBytes: Uint8Array): Promise<string> {
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

  return parts.join("\n");
}

async function makeFixture() {
  const sourceDocument = await PDFDocument.create();

  sourceDocument.addPage([612, 792]);

  const sourcePdf = await sourceDocument.save();
  const now = 1_800_000_000;
  const envelope: EnvelopeRecord = {
    completedAt: now,
    createdAt: now - 500,
    declinedAt: null,
    evidenceKey: null,
    id: "envelope-1",
    pageCount: 1,
    sentAt: now - 400,
    signedPdfKey: null,
    sourcePdfFilename: "umowa.pdf",
    sourcePdfHash: sha256Hex(sourcePdf),
    sourcePdfKey: "source.pdf",
    sourcePdfSizeBytes: sourcePdf.byteLength,
    status: "completed",
    title: TITLE,
    updatedAt: now,
    userId: "user-1",
    voidedAt: null,
  };
  const signers: SignerRecord[] = [
    {
      createdAt: now - 500,
      email: "lukasz@example.com",
      id: "signer-1",
      name: SIGNER_NAME,
      signedAt: now - 100,
      signOrder: 1,
      status: "signed",
      updatedAt: now - 100,
    },
    {
      createdAt: now - 500,
      email: "yamada@example.com",
      id: "signer-2",
      name: SECOND_SIGNER_NAME,
      signedAt: now,
      signOrder: 2,
      status: "signed",
      updatedAt: now,
    },
  ];
  const baseField = {
    createdAt: now - 500,
    envelopeId: envelope.id,
    height: 0.05,
    page: 1,
    required: true,
    submittedAt: now - 100,
    updatedAt: now - 100,
    width: 0.4,
    x: 0.1,
  };
  const fields: FieldRecord[] = [
    {
      ...baseField,
      id: "field-1",
      inputMethod: "typed",
      signerId: "signer-1",
      type: "signature",
      value: SIGNER_NAME,
      y: 0.1,
    },
    {
      ...baseField,
      id: "field-2",
      inputMethod: "typed",
      signerId: "signer-2",
      type: "signature",
      value: SECOND_SIGNER_NAME,
      y: 0.2,
    },
    {
      ...baseField,
      id: "field-3",
      signerId: "signer-1",
      type: "text",
      value: TEXT_VALUE,
      y: 0.3,
    },
    {
      ...baseField,
      id: "field-4",
      signerId: "signer-1",
      type: "text",
      value: "first line\nsecond line",
      y: 0.4,
    },
  ];
  const auditEvents: AuditEventRecord[] = [
    {
      actorEmail: "lukasz@example.com",
      actorType: "signer",
      createdAt: now - 100,
      envelopeId: envelope.id,
      event: "signed",
      id: "event-1",
      ipAddress: "203.0.113.7",
      metadata: {
        signerEmail: "lukasz@example.com",
        signerId: "signer-1",
        signerName: SIGNER_NAME,
      },
      userAgent: "Mozilla/5.0 (テスト)",
    },
  ];
  const storageService = {
    getObject: async () => ({
      body: sourcePdf,
      contentLength: sourcePdf.byteLength,
      contentType: "application/pdf",
    }),
  } as unknown as StorageService;

  return { auditEvents, envelope, fields, signers, storageService };
}

const saveUnsealed = (pdfDocument: PDFDocument) => pdfDocument.save();

test("the signed PDF stamps values in any of the supported scripts", async () => {
  const fixture = await makeFixture();
  const pdfBytes = await renderFinalizedEnvelopePdf(
    {
      auditEvents: fixture.auditEvents,
      completedAt: fixture.envelope.completedAt!,
      envelope: fixture.envelope,
      fields: fixture.fields,
      signers: fixture.signers,
      sourcePdfKey: fixture.envelope.sourcePdfKey,
    },
    { seal: saveUnsealed, storageService: fixture.storageService },
  );
  const text = (await extractText(pdfBytes)).replace(/\s+/g, " ");

  assert.ok(text.includes(SIGNER_NAME));
  assert.ok(text.includes(SECOND_SIGNER_NAME));
  assert.ok(text.includes(TEXT_VALUE));
  // A line break in a value used to fail too. It is drawn as a space.
  assert.ok(text.includes("first line second line"));
  // Only the glyphs in use are embedded, next to the script font.
  assert.ok(
    pdfBytes.byteLength < 500_000,
    `signed PDF is ${String(pdfBytes.byteLength)} bytes`,
  );
});

test("the certificate prints names, titles and browser strings as they are", async () => {
  const fixture = await makeFixture();
  const pdfBytes = await renderEnvelopeCertificatePdf(
    {
      auditEvents: fixture.auditEvents,
      envelope: fixture.envelope,
      signers: fixture.signers,
    },
    { seal: saveUnsealed },
  );
  const text = (await extractText(pdfBytes)).replace(/\s+/g, " ");

  assert.ok(text.includes("Łódź"));
  assert.ok(text.includes("業務委託契約書"));
  assert.ok(text.includes(SIGNER_NAME));
  assert.ok(text.includes(SECOND_SIGNER_NAME));
  assert.ok(text.includes("テスト"));
  assert.ok(
    pdfBytes.byteLength < 200_000,
    `certificate is ${String(pdfBytes.byteLength)} bytes`,
  );

  const reloaded = await PDFDocument.load(pdfBytes);

  assert.ok(reloaded.getTitle()?.includes("業務委託契約書"));
});

test("the certificate names the people who were sent a copy", async () => {
  const fixture = await makeFixture();
  const copyRecipients = [
    { email: "zofia@example.com", name: "Zofia Wiśniewska" },
  ];
  const render = (redactForRecipients: boolean) =>
    renderEnvelopeCertificatePdf(
      {
        auditEvents: fixture.auditEvents,
        copyRecipients,
        envelope: fixture.envelope,
        redactForRecipients,
        signers: fixture.signers,
      },
      { seal: saveUnsealed },
    ).then(async (bytes) => (await extractText(bytes)).replace(/\s+/g, " "));
  const full = await render(false);

  assert.ok(full.includes("Copy recipients"));
  assert.ok(full.includes("They did not sign it."));
  assert.ok(full.includes("Zofia Wiśniewska <zofia@example.com>"));

  // The signers' own copy leaves addresses out, as it does for signers.
  const redacted = await render(true);

  assert.ok(redacted.includes("Zofia Wiśniewska"));
  assert.ok(!redacted.includes("zofia@example.com"));

  // No section at all when nobody was sent a copy.
  const without = await renderEnvelopeCertificatePdf(
    {
      auditEvents: fixture.auditEvents,
      envelope: fixture.envelope,
      signers: fixture.signers,
    },
    { seal: saveUnsealed },
  );

  assert.ok(!(await extractText(without)).includes("Copy recipients"));
});

test("recipient certificates omit a correction's previous email", async () => {
  const fixture = await makeFixture();
  const previousEmail = "previous.signer@hide.test";
  const auditEvents: AuditEventRecord[] = [
    {
      actorEmail: "sam@example.test",
      actorType: "sender",
      createdAt: 1_800_000_000 - 50,
      envelopeId: fixture.envelope.id,
      event: "signer_corrected",
      id: "event-correction",
      metadata: {
        previousEmail,
        previousName: SIGNER_NAME,
        signerEmail: "lukasz@example.com",
        signerId: "signer-1",
        signerName: SIGNER_NAME,
      },
    },
    ...fixture.auditEvents,
  ];
  const render = (redactForRecipients: boolean) =>
    renderEnvelopeCertificatePdf(
      {
        auditEvents,
        envelope: fixture.envelope,
        redactForRecipients,
        signers: fixture.signers,
      },
      { seal: saveUnsealed },
    ).then(async (bytes) => (await extractText(bytes)).replace(/\s+/g, " "));
  const full = await render(false);
  const redacted = await render(true);

  assert.ok(full.includes(previousEmail));
  assert.ok(full.includes("Signer email corrected from"));
  assert.ok(!redacted.includes(previousEmail));
  assert.ok(redacted.includes("Signer email was corrected"));
});

test("the certificate credits consent recorded after a signer correction", async () => {
  const fixture = await makeFixture();
  const auditEvents: AuditEventRecord[] = [
    {
      actorEmail: "old@example.com",
      actorType: "signer",
      createdAt: 1_799_999_000,
      envelopeId: fixture.envelope.id,
      event: "consented",
      id: "event-old-consent",
      metadata: {
        disclosureVersion: "old-version",
        signerId: "signer-1",
        signerName: SIGNER_NAME,
      },
    },
    {
      actorEmail: "sam@example.test",
      actorType: "sender",
      createdAt: 1_799_999_010,
      envelopeId: fixture.envelope.id,
      event: "signer_corrected",
      id: "event-correction",
      metadata: {
        previousEmail: "old@example.com",
        previousName: SIGNER_NAME,
        signerEmail: "lukasz@example.com",
        signerId: "signer-1",
        signerName: SIGNER_NAME,
      },
    },
    {
      actorEmail: "lukasz@example.com",
      actorType: "signer",
      createdAt: 1_800_000_050,
      envelopeId: fixture.envelope.id,
      event: "consented",
      id: "event-new-consent",
      metadata: {
        disclosureVersion: "new-version",
        signerId: "signer-1",
        signerName: SIGNER_NAME,
      },
    },
    ...fixture.auditEvents,
  ];
  const text = (
    await extractText(
      await renderEnvelopeCertificatePdf(
        {
          auditEvents,
          envelope: fixture.envelope,
          signers: fixture.signers,
        },
        { seal: saveUnsealed },
      ),
    )
  ).replace(/\s+/g, " ");
  const signersSection = text.split("Audit events")[0] ?? "";

  assert.ok(signersSection.includes("disclosure new-version"));
  assert.ok(!signersSection.includes("disclosure old-version"));
});

test("the certificate keeps restored consent after a reversed correction", async () => {
  const fixture = await makeFixture();
  const auditEvents: AuditEventRecord[] = [
    {
      actorEmail: "lukasz@example.com",
      actorType: "signer",
      createdAt: 1_799_999_000,
      envelopeId: fixture.envelope.id,
      event: "consented",
      id: "event-kept-consent",
      metadata: {
        disclosureVersion: "kept-version",
        signerId: "signer-1",
        signerName: SIGNER_NAME,
      },
    },
    {
      actorEmail: "sam@example.test",
      actorType: "sender",
      createdAt: 1_799_999_010,
      envelopeId: fixture.envelope.id,
      event: "signer_corrected",
      id: "event-correction",
      metadata: {
        previousEmail: "lukasz@example.com",
        previousName: SIGNER_NAME,
        signerEmail: "temporary@example.com",
        signerId: "signer-1",
        signerName: SIGNER_NAME,
      },
    },
    {
      actorEmail: "sam@example.test",
      actorType: "sender",
      createdAt: 1_799_999_020,
      envelopeId: fixture.envelope.id,
      event: "signer_corrected",
      id: "event-reversal",
      metadata: {
        previousEmail: "temporary@example.com",
        previousName: SIGNER_NAME,
        reverted: true,
        signerEmail: "lukasz@example.com",
        signerId: "signer-1",
        signerName: SIGNER_NAME,
      },
    },
    ...fixture.auditEvents,
  ];
  const text = (
    await extractText(
      await renderEnvelopeCertificatePdf(
        {
          auditEvents,
          envelope: fixture.envelope,
          signers: fixture.signers,
        },
        { seal: saveUnsealed },
      ),
    )
  ).replace(/\s+/g, " ");
  const signersSection = text.split("Audit events")[0] ?? "";

  assert.ok(signersSection.includes("disclosure kept-version"));
});

test("numbers and dropdown choices are stamped as text, radio buttons as rings", async () => {
  const fixture = await makeFixture();
  const base = {
    createdAt: 1_800_000_000,
    envelopeId: fixture.envelope.id,
    height: 0.03,
    page: 1,
    required: true,
    signerId: "signer-1",
    submittedAt: 1_800_000_000,
    updatedAt: 1_800_000_000,
    width: 0.3,
    x: 0.1,
  };
  const choiceFields: FieldRecord[] = [
    { ...base, id: "number-1", type: "number", value: "1,250.75", y: 0.5 },
    {
      ...base,
      id: "dropdown-1",
      options: ["Tak", "Nie", "Nie wiem"],
      type: "dropdown",
      value: "Nie wiem",
      y: 0.55,
    },
    // An optional dropdown that was left alone: nothing to stamp.
    {
      ...base,
      id: "dropdown-2",
      options: ["One", "Two"],
      required: false,
      submittedAt: null,
      type: "dropdown",
      value: null,
      y: 0.6,
    },
    {
      ...base,
      checked: true,
      groupId: "group-1",
      id: "radio-1",
      label: "Yes",
      type: "radio",
      width: 0.03,
      y: 0.65,
    },
    {
      ...base,
      checked: false,
      groupId: "group-1",
      id: "radio-2",
      label: "No",
      type: "radio",
      width: 0.03,
      y: 0.7,
    },
  ];
  const render = (fields: FieldRecord[]) =>
    renderFinalizedEnvelopePdf(
      {
        auditEvents: fixture.auditEvents,
        completedAt: fixture.envelope.completedAt!,
        envelope: fixture.envelope,
        fields,
        signers: fixture.signers,
        sourcePdfKey: fixture.envelope.sourcePdfKey,
      },
      { seal: saveUnsealed, storageService: fixture.storageService },
    );
  const pdfBytes = await render([...fixture.fields, ...choiceFields]);
  const text = (await extractText(pdfBytes)).replace(/\s+/g, " ");

  assert.ok(text.includes("1,250.75"));
  assert.ok(text.includes("Nie wiem"));
  // The choices that were not picked are not on the document.
  assert.ok(!text.includes("Tak"));
  assert.ok(!text.includes("One"));

  // The two radio buttons add drawing to the page: two rings and one dot.
  // Without them the same document is smaller.
  const withoutRadios = await render([
    ...fixture.fields,
    ...choiceFields.filter((field) => field.type !== "radio"),
  ]);
  const chosenOnly = await render([
    ...fixture.fields,
    ...choiceFields.filter((field) => field.id !== "radio-2"),
  ]);

  assert.ok(pdfBytes.byteLength > chosenOnly.byteLength);
  assert.ok(chosenOnly.byteLength > withoutRadios.byteLength);
});

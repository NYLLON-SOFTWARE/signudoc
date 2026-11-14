import { randomUUID } from "node:crypto";

import { type Branding } from "./branding.ts";
import {
  type DbExecutor,
  type DbPool,
  getDb,
  queryMany,
  queryOne,
  withTransaction,
} from "./db/connection.ts";
import {
  deadlineFromDays,
  formatDeadline,
  isEnvelopeExpired,
  signingLinkLifetimeSeconds,
} from "./envelope-deadline.ts";
import {
  countAnswerableFields,
  describeChoiceFieldProblem,
  findChoiceFieldProblem,
} from "./field-choices.ts";
import {
  changeDeadlineResponseSchema,
  changeRemindersResponseSchema,
  envelopeListFiltersSchema,
  type AuditEventRecord,
  type ChangeDeadlineResponse,
  type ChangeRemindersResponse,
  envelopeCreateResponseSchema,
  envelopePageSchema,
  envelopeRecordSchema,
  sendEnvelopeResponseSchema,
  voidEnvelopeResponseSchema,
  type CreateEnvelopeResponse,
  type EnvelopeListFilters,
  type EnvelopePageRecord,
  type EnvelopeRecord,
  type SendEnvelopeResponse,
  type VoidEnvelopeResponse,
} from "./schemas/envelope.ts";
import {
  fieldPlacementSchema,
  fieldRecordSchema,
  replaceFieldsResponseSchema,
  replaceFieldsSchema,
  type FieldRecord,
  type ReplaceFieldsResponse,
} from "./schemas/field.ts";
import {
  correctSentSignerResponseSchema,
  correctSentSignerSchema,
  duplicateCopyRecipientEmailMessage,
  duplicateSignerEmailMessage,
  replaceSignersResponseSchema,
  replaceSignersSchema,
  signerRecordSchema,
  type CopyRecipientRecord,
  type CorrectSentSignerResponse,
  type ReplaceSignersResponse,
  type SignerRecord,
} from "./schemas/signer.ts";
import {
  describePart11SignerProblem,
  findSignerAccounts,
  parseSignatureMeaning,
  signatureMeaningLabel,
} from "./part11.ts";
import { getBranding, readStoredSettings } from "./settings.ts";
import { type SignatureMeaning } from "./types/domain.ts";
import { importPdfDocument } from "./services/document-import.ts";
import {
  describeSignerCorrectedEvent,
  listAuditEventsForEnvelope,
  lockEnvelopeAuditChain,
  recordAuditEvent,
  recordEmailSent,
} from "./services/audit.ts";
import { createEmailService, type EmailService } from "./services/email.ts";
import { withUserEmailLegalFooter } from "./services/email-legal-footer.ts";
import { buildSigningInvitationEmail } from "./services/signing-invitation-email.ts";
import {
  storeEnvelopeCertificatePdf,
  storeRecipientEnvelopeCertificatePdf,
} from "./services/pdf-finalize.ts";
import {
  issueSigningLink,
  type IssuedSigningLink,
} from "./services/signing-links.ts";
import {
  buildEnvelopeCertificateKey,
  buildEnvelopeOriginalPdfKey,
  buildEnvelopeThumbnailKey,
} from "./services/storage-keys.ts";
import {
  configuredSigningProvider,
  signingProviderById,
  type SigningProviderId,
} from "./services/signing-providers.ts";
import {
  createStorageService,
  StorageObjectNotFoundError,
  type StorageObjectStream,
  type StorageService,
} from "./services/storage.ts";
import {
  assertThumbnailImage,
  buildThumbnailEtag,
  matchesEtag,
  THUMBNAIL_CONTENT_TYPE,
} from "./services/thumbnails.ts";
import {
  formatReminderAvailableAt,
  getManualNudgeAvailableAt,
  isManualNudgeAvailable,
} from "./services/reminders.ts";
import { PERMITTED_USE_VERSION } from "./permitted-uses.ts";
import { hashAccessCode } from "./signer-checks.ts";
import { escapeHtml } from "./utils/html.ts";

type CreateDraftEnvelopeOptions = {
  database?: DbPool;
  storageService?: StorageService;
};

type CreateDraftEnvelopeInput = {
  sourcePdf: {
    body: Uint8Array;
    contentType?: string | null;
    filename: string;
  };
  title: string;
};

type SendDraftEnvelopeInput = {
  /** How many days signers get. The default applies when left out. */
  expiresInDays?: number;
  /** Days between automatic reminders. Null or left out means none. */
  reminderIntervalDays?: number | null;
  /**
   * Advanced or qualified: each signer signs with a certificate in their
   * own name through the install's signing provider. Simple by default.
   */
  signatureLevel?: "advanced" | "qualified" | "simple";
  ipAddress?: string | null;
  senderEmail: string;
  senderName: string;
  userAgent?: string | null;
};

type VoidEnvelopeInput = {
  ipAddress?: string | null;
  /** Why it is voided. Required for a Part 11 envelope. */
  reason?: string | null;
  senderEmail: string;
  senderName: string;
  userAgent?: string | null;
};

type CorrectSentEnvelopeSignerContext = {
  ipAddress?: string | null;
  senderEmail: string;
  senderName: string;
  userAgent?: string | null;
};

type CorrectSentEnvelopeSignerOptions = {
  database?: DbPool;
  emailService?: EmailService;
  nowUnixTimestamp?: number;
};

type SendDraftEnvelopeOptions = {
  database?: DbPool;
};

type VoidEnvelopeOptions = {
  database?: DbPool;
};

type EnvelopeRow = {
  completedAt: number | null;
  createdAt: number;
  declinedAt: number | null;
  evidenceKey: string | null;
  expiresAt: number | null;
  id: string;
  reminderIntervalDays: number | null;
  pageCount: number;
  part11: boolean;
  sentAt: number | null;
  signatureLevel: "advanced" | "qualified" | "simple";
  signatureProvider: string | null;
  signedPdfKey: string | null;
  sourcePdfFilename: string;
  sourcePdfHash: string;
  sourcePdfKey: string;
  sourcePdfSizeBytes: number;
  status: EnvelopeRecord["status"];
  title: string;
  updatedAt: number;
  userId: string;
  voidedAt: number | null;
};

type SignerRow = {
  createdAt: number;
  declineReason: string | null;
  declinedAt: number | null;
  email: string;
  envelopeId: string;
  id: string;
  lastNotifiedAt: number | null;
  lastNudgedAt: number | null;
  name: string;
  signatureMeaning: SignatureMeaning | null;
  signedAt: number | null;
  signOrder: number;
  signingTokenExpiresAt: number | null;
  signingTokenHash: string | null;
  status: SignerRecord["status"];
  turnStartedAt: number | null;
  updatedAt: number;
};

type FieldRow = {
  checked: boolean | null;
  createdAt: number;
  envelopeId: string;
  groupId: string | null;
  height: number;
  id: string;
  imageKey: string | null;
  inputMethod: FieldRecord["inputMethod"] | null;
  label: string | null;
  options: string[] | null;
  page: number;
  required: boolean;
  signerId: string;
  submittedAt: number | null;
  type: FieldRecord["type"];
  updatedAt: number;
  value: string | null;
  width: number;
  x: number;
  y: number;
};

function shouldCountFieldForSignerSummary(
  field: Pick<FieldRecord, "required" | "type">,
): boolean {
  if (field.type === "signature" || field.type === "initials") {
    return true;
  }

  if (
    field.type === "text" ||
    field.type === "number" ||
    field.type === "dropdown"
  ) {
    return true;
  }

  if (field.type === "checkbox" || field.type === "radio") {
    return field.required;
  }

  return false;
}

type EnvelopePageRow = {
  envelopeId: string;
  heightPt: number;
  id: string;
  pageNumber: number;
  widthPt: number;
};

type PersistedSignerRecord = SignerRecord & {
  envelopeId: string;
  id: string;
  signOrder: number;
};

type PersistedFieldRecord = FieldRecord & {
  envelopeId: string;
  id: string;
  signerId: string;
};

export type DashboardEnvelopeListItem = {
  contextLine: string;
  createdAtLabel: string;
  /** Out for signature and past its deadline. */
  expired?: boolean;
  id: string;
  searchableEmails: readonly string[];
  status: EnvelopeRecord["status"];
  /** What the status pill says: the status, or how far signing has got. */
  statusLabel: string;
  title: string;
};

type ReviewFieldSummary =
  | "Checkbox"
  | "Date"
  | "Dropdown"
  | "Initials"
  | "Number"
  | "Radio group"
  | "Signature"
  | "Text";

export type ReviewSignerSummary = {
  email: string;
  fieldSummaries: readonly ReviewFieldSummary[];
  id: string;
  name: string;
  order: number;
};

export type ReviewEnvelopeData = {
  canSend: boolean;
  /**
   * The install's signing provider, when the sender may choose signatures
   * in the signers' own names. Null without one, or in Part 11 mode.
   */
  signingProvider: { name: string } | null;
  copyRecipients: readonly CopyRecipientRecord[];
  disabledReason: string | null;
  envelopeId: string;
  filename: string;
  isEmpty: boolean;
  pageCount: number;
  signers: readonly ReviewSignerSummary[];
  sizeLabel: string;
  status: EnvelopeRecord["status"];
  title: string;
};

export type DraftSignerStepSigner = {
  email: string;
  /** Set on the signers step only. */
  hasAccessCode?: boolean;
  id: string;
  name: string;
  order: number;
  requireEmailCode?: boolean;
  /** Set on the signers step only. */
  signatureMeaning?: SignatureMeaning | null;
};

export type DraftSignerStepData = {
  copyRecipients: readonly CopyRecipientRecord[];
  envelopeId: string;
  /** Part 11 mode is on, so each signer needs a meaning and an account. */
  part11Mode?: boolean;
  signers: readonly DraftSignerStepSigner[];
  status: EnvelopeRecord["status"];
};

export type PrepareEnvelopeData = {
  envelopeId: string;
  fields: readonly FieldRecord[];
  pageCount: number;
  pages: readonly EnvelopePageRecord[];
  pdfUrl: string;
  signers: readonly DraftSignerStepSigner[];
  status: EnvelopeRecord["status"];
  title: string;
};

export type EnvelopeDetailSignerView = {
  email: string;
  id: string;
  metaLabel: string;
  name: string;
  order: number;
  status: "declined" | "pending" | "signed" | "waiting";
  statusDateLabel?: string;
};

export type EnvelopeDetailTimelineItem = {
  description: string;
  id: string;
  timestamp: string;
  tone: "accent" | "danger" | "neutral" | "success";
};

export type EnvelopeDetailManualReminderState = {
  canSend: boolean;
  nextAvailableAtLabel: string | null;
};

export type EnvelopeDetailDeadline = {
  /** True once the deadline has passed and nobody can sign any more. */
  expired: boolean;
  /** Null for an envelope sent before deadlines existed. */
  expiresAtLabel: string | null;
};

export type EnvelopeDetailData = {
  /** People who get a copy of the finished document without signing. */
  copyRecipients: readonly CopyRecipientRecord[];
  createdAtLabel: string;
  /** Set while the envelope is out for signature. */
  deadline: EnvelopeDetailDeadline | null;
  /** Days between automatic reminders while it is out. Null when off. */
  reminderIntervalDays: number | null;
  envelopeId: string;
  manualReminder: EnvelopeDetailManualReminderState | null;
  /** Sent in Part 11 mode: a void needs a reason. */
  part11: boolean;
  /**
   * How signers sign, when not with SignuDoc's own simple signature: for
   * example "Qualified electronic signatures through eID Easy".
   */
  signatureTypeLabel: string | null;
  signers: readonly EnvelopeDetailSignerView[];
  status: EnvelopeRecord["status"];
  timeline: readonly EnvelopeDetailTimelineItem[];
  title: string;
};

export type DraftEnvelopeDocument = {
  body: Uint8Array;
  contentLength: number;
  contentType: string;
  fileName: string;
};

/**
 * Copy recipients are stored after every signer. Signers use 1 to 10, and a
 * rewrite of the signer list parks rows 1000 higher for a moment.
 */
const COPY_RECIPIENT_SIGN_ORDER_BASE = 500;

export class EnvelopeMutationError extends Error {
  readonly statusCode: number;

  constructor(message: string, statusCode: number) {
    super(message);
    this.name = "EnvelopeMutationError";
    this.statusCode = statusCode;
  }
}

export class EnvelopeDocumentAccessError extends Error {
  readonly statusCode: number;

  constructor(message: string, statusCode: number) {
    super(message);
    this.name = "EnvelopeDocumentAccessError";
    this.statusCode = statusCode;
  }
}

export type DraftEnvelopeResult = {
  envelope: EnvelopeRecord;
  pages: EnvelopePageRecord[];
};

export type ReplaceDraftSignersResult = ReplaceSignersResponse;
export type ReplaceDraftFieldsResult = ReplaceFieldsResponse;
export type SendDraftEnvelopeResult = SendEnvelopeResponse;
export type VoidEnvelopeResult = VoidEnvelopeResponse;
export type CorrectSentSignerResult = CorrectSentSignerResponse;

const FIELD_TYPE_SUMMARY_LABELS: Record<
  FieldRecord["type"],
  ReviewFieldSummary
> = {
  checkbox: "Checkbox",
  date: "Date",
  dropdown: "Dropdown",
  initials: "Initials",
  number: "Number",
  radio: "Radio group",
  signature: "Signature",
  text: "Text",
};

const FIELD_TYPE_SORT_ORDER: Record<FieldRecord["type"], number> = {
  checkbox: 6,
  date: 2,
  dropdown: 5,
  initials: 1,
  number: 4,
  radio: 7,
  signature: 0,
  text: 3,
};

const TIMELINE_TONE_MAP: Record<
  AuditEventRecord["event"],
  EnvelopeDetailTimelineItem["tone"]
> = {
  completed: "success",
  consented: "neutral",
  created: "accent",
  deadline_changed: "neutral",
  declined: "danger",
  email_sent: "neutral",
  expired: "danger",
  reauthentication_failed: "danger",
  reminded_auto: "neutral",
  signer_corrected: "neutral",
  reminded_manual: "neutral",
  sent: "neutral",
  signed: "success",
  verification_failed: "danger",
  verified: "neutral",
  viewed: "neutral",
  voided: "danger",
};

const shortDateFormatter = new Intl.DateTimeFormat("en-US", {
  day: "numeric",
  month: "short",
  timeZone: "UTC",
  year: "numeric",
});

const longDateFormatter = new Intl.DateTimeFormat("en-US", {
  day: "numeric",
  month: "long",
  timeZone: "UTC",
  year: "numeric",
});

const timelineDateFormatter = new Intl.DateTimeFormat("en-US", {
  day: "numeric",
  hour: "numeric",
  minute: "2-digit",
  month: "short",
  timeZone: "UTC",
});

export async function createDraftEnvelope(
  userId: string,
  input: CreateDraftEnvelopeInput,
  {
    database = getDb(),
    storageService = createStorageService(),
  }: CreateDraftEnvelopeOptions = {},
): Promise<DraftEnvelopeResult> {
  const importedPdf = await importPdfDocument({
    body: input.sourcePdf.body,
    contentType: input.sourcePdf.contentType,
    filename: input.sourcePdf.filename,
  });
  const envelopeId = randomUUID();
  const now = Math.floor(Date.now() / 1000);
  const sourcePdfKey = buildEnvelopeOriginalPdfKey({
    envelopeId,
    userId,
  });

  await storageService.putObject({
    body: input.sourcePdf.body,
    contentType: "application/pdf",
    key: sourcePdfKey,
  });

  try {
    const envelope = envelopeRecordSchema.parse({
      completedAt: null,
      createdAt: now,
      declinedAt: null,
      evidenceKey: null,
      id: envelopeId,
      pageCount: importedPdf.pageCount,
      sentAt: null,
      signedPdfKey: null,
      sourcePdfFilename: importedPdf.filename,
      sourcePdfHash: importedPdf.sourceHash,
      sourcePdfKey,
      sourcePdfSizeBytes: importedPdf.sizeBytes,
      status: "draft",
      title: input.title,
      updatedAt: now,
      userId,
      voidedAt: null,
    });
    const pages = importedPdf.pages.map((page) =>
      envelopePageSchema.parse({
        envelopeId,
        heightPt: page.heightPt,
        id: randomUUID(),
        pageNumber: page.pageNumber,
        widthPt: page.widthPt,
      }),
    );

    await withTransaction(async (tx) => {
      await tx.query(
        `
          INSERT INTO envelopes (
            id,
            user_id,
            title,
            status,
            source_pdf_key,
            source_pdf_filename,
            source_pdf_size_bytes,
            page_count,
            signed_pdf_key,
            evidence_key,
            source_pdf_hash,
            sent_at,
            completed_at,
            declined_at,
            voided_at,
            created_at,
            updated_at
          ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17
          )
        `,
        [
          envelope.id,
          envelope.userId,
          envelope.title,
          envelope.status,
          envelope.sourcePdfKey,
          envelope.sourcePdfFilename,
          envelope.sourcePdfSizeBytes,
          envelope.pageCount,
          envelope.signedPdfKey,
          envelope.evidenceKey,
          envelope.sourcePdfHash,
          envelope.sentAt,
          envelope.completedAt,
          envelope.declinedAt,
          envelope.voidedAt,
          envelope.createdAt,
          envelope.updatedAt,
        ],
      );

      for (const page of pages) {
        await tx.query(
          `
            INSERT INTO envelope_pages (
              id,
              envelope_id,
              page_number,
              width_pt,
              height_pt
            ) VALUES ($1, $2, $3, $4, $5)
          `,
          [
            page.id,
            page.envelopeId,
            page.pageNumber,
            page.widthPt,
            page.heightPt,
          ],
        );
      }

      await recordAuditEvent(
        {
          actorEmail: null,
          actorType: "sender",
          createdAt: now,
          envelopeId,
          event: "created",
          metadata: null,
        },
        tx,
      );
    }, database);

    return {
      envelope,
      pages,
    };
  } catch (error) {
    await storageService.deleteObject(sourcePdfKey).catch(() => undefined);
    throw error;
  }
}

export function buildCreateEnvelopeResponse(
  result: DraftEnvelopeResult,
): CreateEnvelopeResponse {
  return envelopeCreateResponseSchema.parse({
    envelopeId: result.envelope.id,
    pageCount: result.envelope.pageCount,
    redirectPath: `/envelopes/${result.envelope.id}/signers`,
    sourcePdfFilename: result.envelope.sourcePdfFilename,
    sourcePdfSizeBytes: result.envelope.sourcePdfSizeBytes,
    title: result.envelope.title,
  });
}

function mapEnvelopeRow(row: EnvelopeRow): EnvelopeRecord {
  return envelopeRecordSchema.parse(row);
}

function mapSignerRow(row: SignerRow): PersistedSignerRecord {
  return signerRecordSchema.parse(row) as PersistedSignerRecord;
}

function mapEnvelopePageRow(row: EnvelopePageRow): EnvelopePageRecord {
  return envelopePageSchema.parse(row);
}

function mapFieldRow(row: FieldRow): PersistedFieldRecord {
  return fieldRecordSchema.parse({
    checked: row.checked,
    createdAt: row.createdAt,
    envelopeId: row.envelopeId,
    groupId: row.groupId ?? undefined,
    height: row.height,
    id: row.id,
    imageKey: row.imageKey,
    inputMethod: row.inputMethod,
    label: row.label ?? undefined,
    options: row.options ?? undefined,
    page: row.page,
    required: row.required,
    signerId: row.signerId,
    submittedAt: row.submittedAt,
    type: row.type,
    updatedAt: row.updatedAt,
    value: row.value ?? undefined,
    width: row.width,
    x: row.x,
    y: row.y,
  }) as PersistedFieldRecord;
}

function escapeLike(value: string): string {
  return value
    .replaceAll("\\", "\\\\")
    .replaceAll("%", "\\%")
    .replaceAll("_", "\\_");
}

function buildInClausePlaceholders(length: number, startAt = 1): string {
  return Array.from(
    { length },
    (_, index) => `$${String(index + startAt)}`,
  ).join(", ");
}

function pluralize(count: number, singular: string, plural = `${singular}s`) {
  return `${count} ${count === 1 ? singular : plural}`;
}

function formatShortDate(timestamp: number): string {
  return shortDateFormatter.format(new Date(timestamp * 1000));
}

function formatLongDate(timestamp: number): string {
  return longDateFormatter.format(new Date(timestamp * 1000));
}

function formatTimelineTimestamp(timestamp: number): string {
  return timelineDateFormatter.format(new Date(timestamp * 1000));
}

function formatFileSize(sizeBytes: number): string {
  if (sizeBytes < 1024 * 1024) {
    return `${(sizeBytes / 1024).toFixed(1)} KB`;
  }

  return `${(sizeBytes / (1024 * 1024)).toFixed(1)} MB`;
}

async function getEnvelopeByIdForUser(
  userId: string,
  envelopeId: string,
  database: DbExecutor,
): Promise<EnvelopeRecord | null> {
  const row = await queryOne<EnvelopeRow>(
    database,
    `
      SELECT
        id,
        user_id AS "userId",
        title,
        status,
        source_pdf_key AS "sourcePdfKey",
        source_pdf_filename AS "sourcePdfFilename",
        source_pdf_size_bytes AS "sourcePdfSizeBytes",
        page_count AS "pageCount",
        signed_pdf_key AS "signedPdfKey",
        evidence_key AS "evidenceKey",
        source_pdf_hash AS "sourcePdfHash",
        sent_at AS "sentAt",
        completed_at AS "completedAt",
        declined_at AS "declinedAt",
        voided_at AS "voidedAt",
        expires_at AS "expiresAt",
        reminder_interval_days AS "reminderIntervalDays",
        part11,
        signature_level AS "signatureLevel",
        signature_provider AS "signatureProvider",
        created_at AS "createdAt",
        updated_at AS "updatedAt"
      FROM envelopes
      WHERE id = $1 AND user_id = $2
    `,
    [envelopeId, userId],
  );

  return row ? mapEnvelopeRow(row) : null;
}

async function listSignersForEnvelopeIds(
  envelopeIds: readonly string[],
  database: DbExecutor,
): Promise<Map<string, PersistedSignerRecord[]>> {
  if (envelopeIds.length === 0) {
    return new Map();
  }

  const placeholders = buildInClausePlaceholders(envelopeIds.length);
  const rows = await queryMany<SignerRow>(
    database,
    `
      SELECT
        id,
        envelope_id AS "envelopeId",
        name,
        email,
        sign_order AS "signOrder",
        status,
        signing_token_hash AS "signingTokenHash",
        signing_token_expires_at AS "signingTokenExpiresAt",
        turn_started_at AS "turnStartedAt",
        last_notified_at AS "lastNotifiedAt",
        last_nudged_at AS "lastNudgedAt",
        signed_at AS "signedAt",
        declined_at AS "declinedAt",
        decline_reason AS "declineReason",
        signature_meaning AS "signatureMeaning",
        created_at AS "createdAt",
        updated_at AS "updatedAt"
      FROM signers
      WHERE envelope_id IN (${placeholders})
        AND role = 'signer'
      ORDER BY envelope_id ASC, sign_order ASC, id ASC
    `,
    envelopeIds,
  );

  const signersByEnvelope = new Map<string, PersistedSignerRecord[]>();

  for (const row of rows) {
    const signer = mapSignerRow(row);
    const existing = signersByEnvelope.get(signer.envelopeId);

    if (existing) {
      existing.push(signer);
      continue;
    }

    signersByEnvelope.set(signer.envelopeId, [signer]);
  }

  return signersByEnvelope;
}

async function listSignersForEnvelopeId(
  envelopeId: string,
  database: DbExecutor,
): Promise<PersistedSignerRecord[]> {
  return (
    (await listSignersForEnvelopeIds([envelopeId], database)).get(envelopeId) ??
    []
  );
}

/**
 * The people who get a copy of the finished document without signing. They
 * are rows of the signers table with role 'cc', which every other query
 * here leaves out.
 */
export async function listCopyRecipientsForEnvelopeIds(
  envelopeIds: readonly string[],
  database: DbExecutor,
): Promise<Map<string, CopyRecipientRecord[]>> {
  const recipientsByEnvelope = new Map<string, CopyRecipientRecord[]>();

  if (envelopeIds.length === 0) {
    return recipientsByEnvelope;
  }

  const rows = await queryMany<CopyRecipientRecord & { envelopeId: string }>(
    database,
    `
      SELECT id, envelope_id AS "envelopeId", name, email
      FROM signers
      WHERE envelope_id IN (${buildInClausePlaceholders(envelopeIds.length)})
        AND role = 'cc'
      ORDER BY envelope_id ASC, sign_order ASC, id ASC
    `,
    envelopeIds,
  );

  for (const { envelopeId, ...recipient } of rows) {
    const existing = recipientsByEnvelope.get(envelopeId);

    if (existing) {
      existing.push(recipient);
    } else {
      recipientsByEnvelope.set(envelopeId, [recipient]);
    }
  }

  return recipientsByEnvelope;
}

export async function listCopyRecipientsForEnvelopeId(
  envelopeId: string,
  database: DbExecutor,
): Promise<CopyRecipientRecord[]> {
  return (
    (await listCopyRecipientsForEnvelopeIds([envelopeId], database)).get(
      envelopeId,
    ) ?? []
  );
}

async function listSignerCheckSettings(
  envelopeId: string,
  database: DbExecutor,
): Promise<
  Map<
    string,
    {
      hasAccessCode: boolean;
      requireEmailCode: boolean;
      signatureMeaning: SignatureMeaning | null;
    }
  >
> {
  const rows = await queryMany<{
    hasAccessCode: boolean;
    id: string;
    requireEmailCode: boolean;
    signatureMeaning: string | null;
  }>(
    database,
    `
      SELECT
        id,
        access_code_hash IS NOT NULL AS "hasAccessCode",
        require_email_code AS "requireEmailCode",
        signature_meaning AS "signatureMeaning"
      FROM signers
      WHERE envelope_id = $1
    `,
    [envelopeId],
  );

  return new Map(
    rows.map((row) => [
      row.id,
      {
        hasAccessCode: Boolean(row.hasAccessCode),
        requireEmailCode: Boolean(row.requireEmailCode),
        signatureMeaning: parseSignatureMeaning(row.signatureMeaning),
      },
    ]),
  );
}

async function listEnvelopePagesForEnvelopeId(
  envelopeId: string,
  database: DbExecutor,
): Promise<EnvelopePageRecord[]> {
  const rows = await queryMany<EnvelopePageRow>(
    database,
    `
      SELECT
        id,
        envelope_id AS "envelopeId",
        page_number AS "pageNumber",
        width_pt AS "widthPt",
        height_pt AS "heightPt"
      FROM envelope_pages
      WHERE envelope_id = $1
      ORDER BY page_number ASC, id ASC
    `,
    [envelopeId],
  );

  return rows.map(mapEnvelopePageRow);
}

async function listFieldsForEnvelopeIds(
  envelopeIds: readonly string[],
  database: DbExecutor,
): Promise<Map<string, PersistedFieldRecord[]>> {
  if (envelopeIds.length === 0) {
    return new Map();
  }

  const placeholders = buildInClausePlaceholders(envelopeIds.length);
  const rows = await queryMany<FieldRow>(
    database,
    `
      SELECT
        id,
        envelope_id AS "envelopeId",
        signer_id AS "signerId",
        type,
        page,
        x,
        y,
        width,
        height,
        required,
        label,
        input_method AS "inputMethod",
        value,
        image_key AS "imageKey",
        checked,
        options,
        group_id AS "groupId",
        submitted_at AS "submittedAt",
        created_at AS "createdAt",
        updated_at AS "updatedAt"
      FROM fields
      WHERE envelope_id IN (${placeholders})
      ORDER BY envelope_id ASC, page ASC, created_at ASC, id ASC
    `,
    envelopeIds,
  );

  const fieldsByEnvelope = new Map<string, PersistedFieldRecord[]>();

  for (const row of rows) {
    const field = mapFieldRow(row);
    const existing = fieldsByEnvelope.get(field.envelopeId);

    if (existing) {
      existing.push(field);
      continue;
    }

    fieldsByEnvelope.set(field.envelopeId, [field]);
  }

  return fieldsByEnvelope;
}

function buildDashboardContextLine(
  envelope: EnvelopeRecord,
  signers: readonly PersistedSignerRecord[],
  fields: readonly PersistedFieldRecord[],
): string {
  if (envelope.status === "completed") {
    const sentTo = signers.map((signer) => signer.email).join(", ");
    return sentTo.length > 0 ? `Sent to: ${sentTo}` : "Sent to: —";
  }

  if (envelope.status === "sent") {
    const currentSigner =
      signers.find((signer) => signer.status === "notified") ??
      signers.find((signer) => signer.status === "pending");

    if (isEnvelopeExpired(envelope, Math.floor(Date.now() / 1000))) {
      return `Expired ${formatShortDate(envelope.expiresAt!)} · was waiting on: ${currentSigner?.email ?? "—"}`;
    }

    return `Waiting on: ${currentSigner?.email ?? "—"}`;
  }

  if (envelope.status === "declined") {
    const declinedSigner = signers.find(
      (signer) => signer.status === "declined",
    );
    return `Declined by: ${declinedSigner?.email ?? "—"}`;
  }

  if (envelope.status === "voided") {
    return `Voided on ${formatShortDate(envelope.voidedAt ?? envelope.updatedAt)}`;
  }

  return `${pluralize(signers.length, "signer")} · ${pluralize(fields.length, "field")} placed`;
}

const dashboardStatusLabels: Record<EnvelopeRecord["status"], string> = {
  completed: "Completed",
  declined: "Declined",
  draft: "Draft",
  sent: "Sent",
  voided: "Voided",
};

function buildDashboardStatusLabel(
  envelope: EnvelopeRecord,
  signers: readonly PersistedSignerRecord[],
): string {
  if (isEnvelopeExpired(envelope, Math.floor(Date.now() / 1000))) {
    return "Expired";
  }

  // With one signer "Sent" says it all. With several, say how many are done.
  if (envelope.status === "sent" && signers.length > 1) {
    const signedCount = signers.filter(
      (signer) => signer.status === "signed",
    ).length;

    return `${String(signedCount)} of ${String(signers.length)} signed`;
  }

  return dashboardStatusLabels[envelope.status];
}

function buildFieldsBySigner(
  fields: readonly FieldRecord[],
): Map<string, FieldRecord[]> {
  return fields.reduce<Map<string, FieldRecord[]>>((entries, field) => {
    const existing = entries.get(field.signerId);

    if (existing) {
      existing.push(field);
    } else {
      entries.set(field.signerId, [field]);
    }

    return entries;
  }, new Map());
}

/**
 * What is unfinished about a dropdown or a radio group, in words for the
 * sender, or null when every one of them can be answered.
 */
function describeChoiceProblem(
  signers: readonly PersistedSignerRecord[],
  fields: readonly FieldRecord[],
): string | null {
  const problem = findChoiceFieldProblem(fields);

  if (!problem) {
    return null;
  }

  return describeChoiceFieldProblem(
    problem,
    signers.find((signer) => signer.id === problem.signerId)?.name ??
      "a signer",
  );
}

/** The fields with each group of radio buttons counted once. */
function withRadioGroupsOnce(fields: readonly FieldRecord[]): FieldRecord[] {
  const seenGroups = new Set<string>();

  return fields.filter((field) => {
    if (field.type !== "radio" || !field.groupId) {
      return true;
    }

    if (seenGroups.has(field.groupId)) {
      return false;
    }

    seenGroups.add(field.groupId);

    return true;
  });
}

function getMissingSignatureSigner(
  signers: readonly PersistedSignerRecord[],
  fieldsBySigner: ReadonlyMap<string, readonly FieldRecord[]>,
): PersistedSignerRecord | undefined {
  return signers.find(
    (signer) =>
      !(fieldsBySigner.get(signer.id) ?? []).some(
        (field) => field.type === "signature",
      ),
  );
}

function buildVoidNotificationEmail(input: {
  branding: Branding;
  envelopeId: string;
  envelopeTitle: string;
  senderName: string;
  signerEmail: string;
  signerName: string;
}) {
  const subject = `"${input.envelopeTitle}" was voided by ${input.senderName}`;
  const textBody = [
    `Hi ${input.signerName},`,
    "",
    `${input.senderName} voided "${input.envelopeTitle}" in ${input.branding.productName}.`,
    "The signing process has been canceled. No further action is needed.",
  ].join("\n");
  const htmlBody = [
    `<p>Hi ${escapeHtml(input.signerName)},</p>`,
    `<p>${escapeHtml(input.senderName)} voided &ldquo;${escapeHtml(input.envelopeTitle)}&rdquo; in ${escapeHtml(input.branding.productName)}.</p>`,
    "<p>The signing process has been canceled. No further action is needed.</p>",
  ].join("");
  const legalFooter = withUserEmailLegalFooter(
    {
      htmlBody,
      textBody,
    },
    input.branding,
  );

  return {
    htmlBody: legalFooter.htmlBody,
    subject,
    template: "void_notification" as const,
    textBody: legalFooter.textBody,
    to: input.signerEmail,
  };
}

const SIGNATURE_LEVEL_NAMES = {
  advanced: "advanced electronic signature",
  qualified: "qualified electronic signature",
} as const;

function providerName(id: string | null | undefined): string | null {
  if (!id) {
    return null;
  }

  return (
    signingProviderById(id as SigningProviderId)?.name ??
    (id === "eideasy" ? "eID Easy" : id)
  );
}

function describeSignatureType(envelope: EnvelopeRecord): string | null {
  const level = envelope.signatureLevel;

  if (!level || level === "simple") {
    return null;
  }

  const name = SIGNATURE_LEVEL_NAMES[level];
  const through = providerName(envelope.signatureProvider);

  return `${name[0]!.toUpperCase()}${name.slice(1)}s${through ? ` through ${through}` : ""}`;
}

/** "with a qualified electronic signature through eID Easy", or null. */
function describeProviderSignature(metadata: unknown): string | null {
  if (typeof metadata !== "object" || metadata === null) {
    return null;
  }

  const signature = (metadata as { providerSignature?: unknown })
    .providerSignature;

  if (typeof signature !== "object" || signature === null) {
    return null;
  }

  const { level, provider } = signature as {
    level?: unknown;
    provider?: unknown;
  };

  if (level !== "advanced" && level !== "qualified") {
    return null;
  }

  return `with ${level === "advanced" ? "an" : "a"} ${SIGNATURE_LEVEL_NAMES[level]}${
    typeof provider === "string" ? ` through ${provider}` : ""
  }`;
}

function buildTimelineDescription(event: AuditEventRecord): string {
  const signerName =
    typeof event.metadata?.signerName === "string"
      ? event.metadata.signerName
      : null;
  const signerEmail =
    typeof event.metadata?.signerEmail === "string"
      ? event.metadata.signerEmail
      : null;
  const declineReason =
    typeof event.metadata?.reason === "string" &&
    event.metadata.reason.trim().length > 0
      ? event.metadata.reason.trim()
      : null;
  const targetLabel = signerName ?? event.actorEmail ?? signerEmail ?? "signer";

  switch (event.event) {
    case "created":
      return "Envelope created";
    case "sent":
      return `Sent to ${targetLabel}`;
    case "viewed":
      return `Viewed by ${targetLabel}`;
    case "signed":
      return typeof event.metadata?.part11 === "object" &&
        event.metadata.part11 !== null &&
        "meaning" in event.metadata.part11 &&
        typeof event.metadata.part11.meaning === "string"
        ? `Signed by ${targetLabel} (${signatureMeaningLabel(parseSignatureMeaning(event.metadata.part11.meaning)) ?? event.metadata.part11.meaning}, password given again)`
        : describeProviderSignature(event.metadata)
          ? `Signed by ${targetLabel} ${describeProviderSignature(event.metadata)!}`
          : `Signed by ${targetLabel}`;
    case "declined":
      return declineReason
        ? `Declined by ${targetLabel} — ${declineReason}`
        : `Declined by ${targetLabel}`;
    case "reminded_manual":
      return `Manual reminder sent to ${targetLabel}`;
    case "reminded_auto":
      return `Automatic reminder sent to ${targetLabel}`;
    case "consented":
      return `${targetLabel} agreed to use electronic records and signatures`;
    case "verified":
      return `${targetLabel} confirmed their identity`;
    case "verification_failed":
      return `Wrong identity code entered for ${targetLabel}`;
    case "email_sent":
      return typeof event.metadata?.recipient === "string"
        ? `Email accepted for delivery to ${event.metadata.recipient}`
        : "Email accepted for delivery";
    case "completed":
      return "Final signed PDF and certificate generated";
    case "voided":
      return declineReason
        ? `Envelope voided by sender — ${declineReason}`
        : "Envelope voided by sender";
    case "reauthentication_failed":
      return `Wrong password given while signing for ${targetLabel}`;
    case "deadline_changed":
      return typeof event.metadata?.expiresAt === "number"
        ? `Deadline set to ${formatDeadline(event.metadata.expiresAt)}`
        : "Deadline changed";
    case "expired":
      return "Deadline passed before everyone signed";
    case "signer_corrected":
      return describeSignerCorrectedEvent(event.metadata);
    default:
      return event.event;
  }
}

function buildDetailSignerStatusLabel(
  envelope: EnvelopeRecord,
  signer: PersistedSignerRecord,
  previousSignerName?: string,
): string | undefined {
  if (signer.status === "signed" && signer.signedAt) {
    return `Signed ${formatShortDate(signer.signedAt)}`;
  }

  if (signer.status === "declined" && signer.declinedAt) {
    return `Declined ${formatShortDate(signer.declinedAt)}`;
  }

  if (signer.status === "notified") {
    const sentAt = signer.lastNotifiedAt ?? signer.turnStartedAt;
    if (envelope.status === "voided") {
      return sentAt
        ? `Notified ${formatShortDate(sentAt)}`
        : "Notified before void";
    }

    return sentAt ? `Sent ${formatShortDate(sentAt)}` : undefined;
  }

  if (envelope.status === "draft") {
    return previousSignerName
      ? `Ready to notify after ${previousSignerName}`
      : "Ready to notify after send";
  }

  return "No notification sent";
}

function buildDetailSignerMetaLabel(
  envelope: EnvelopeRecord,
  signer: PersistedSignerRecord,
  assignedFieldCount: number,
): string {
  if (envelope.status === "voided" && signer.status === "notified") {
    return "Last notified signer before void";
  }

  if (signer.status === "declined" && signer.declineReason) {
    return `Decline reason: ${signer.declineReason}`;
  }

  if (envelope.status === "declined" && signer.status === "pending") {
    return "Skipped after decline";
  }

  if (envelope.status === "voided" && signer.status === "pending") {
    return "Not reached before void";
  }

  if (signer.status === "signed") {
    return `${pluralize(assignedFieldCount, "field")} completed`;
  }

  if (signer.status === "notified") {
    return "Current signer";
  }

  return `${pluralize(assignedFieldCount, "field")} assigned`;
}

export async function listEnvelopesForUser(
  userId: string,
  filters: Partial<EnvelopeListFilters> = {},
  database: DbExecutor = getDb(),
): Promise<DashboardEnvelopeListItem[]> {
  const parsedFilters = envelopeListFiltersSchema.parse(filters);
  const values: unknown[] = [userId];
  const clauses = ["user_id = $1"];
  let nextParamIndex = 2;

  if (parsedFilters.status) {
    clauses.push(`status = $${String(nextParamIndex)}`);
    values.push(parsedFilters.status);
    nextParamIndex += 1;
  }

  if (parsedFilters.search) {
    const searchPlaceholder = `$${String(nextParamIndex)}`;
    clauses.push(
      `(
        lower(title) LIKE ${searchPlaceholder} ESCAPE '\\'
        OR EXISTS (
          SELECT 1
          FROM signers
          WHERE signers.envelope_id = envelopes.id
            AND lower(signers.email) LIKE ${searchPlaceholder} ESCAPE '\\'
        )
      )`,
    );
    values.push(`%${escapeLike(parsedFilters.search.toLowerCase())}%`);
    nextParamIndex += 1;
  }

  const limitPlaceholder = `$${String(nextParamIndex)}`;
  values.push(parsedFilters.limit);
  nextParamIndex += 1;
  const offsetPlaceholder = `$${String(nextParamIndex)}`;
  values.push((parsedFilters.page - 1) * parsedFilters.limit);

  const rows = await queryMany<EnvelopeRow>(
    database,
    `
      SELECT
        id,
        user_id AS "userId",
        title,
        status,
        source_pdf_key AS "sourcePdfKey",
        source_pdf_filename AS "sourcePdfFilename",
        source_pdf_size_bytes AS "sourcePdfSizeBytes",
        page_count AS "pageCount",
        signed_pdf_key AS "signedPdfKey",
        evidence_key AS "evidenceKey",
        source_pdf_hash AS "sourcePdfHash",
        sent_at AS "sentAt",
        completed_at AS "completedAt",
        declined_at AS "declinedAt",
        voided_at AS "voidedAt",
        expires_at AS "expiresAt",
        reminder_interval_days AS "reminderIntervalDays",
        part11,
        signature_level AS "signatureLevel",
        signature_provider AS "signatureProvider",
        created_at AS "createdAt",
        updated_at AS "updatedAt"
      FROM envelopes
      WHERE ${clauses.join(" AND ")}
      ORDER BY created_at DESC, id DESC
      LIMIT ${limitPlaceholder} OFFSET ${offsetPlaceholder}
    `,
    values,
  );

  const envelopes = rows.map(mapEnvelopeRow);
  const envelopeIds = envelopes.map((envelope) => envelope.id);
  const [signersByEnvelope, fieldsByEnvelope, copyRecipientsByEnvelope] =
    await Promise.all([
      listSignersForEnvelopeIds(envelopeIds, database),
      listFieldsForEnvelopeIds(envelopeIds, database),
      listCopyRecipientsForEnvelopeIds(envelopeIds, database),
    ]);

  return envelopes.map((envelope) => {
    const signers = signersByEnvelope.get(envelope.id) ?? [];
    const fields = fieldsByEnvelope.get(envelope.id) ?? [];

    return {
      contextLine: buildDashboardContextLine(envelope, signers, fields),
      createdAtLabel: formatShortDate(envelope.createdAt),
      expired: isEnvelopeExpired(envelope, Math.floor(Date.now() / 1000)),
      id: envelope.id,
      // The search on the server matches copy recipients too.
      searchableEmails: [
        ...signers,
        ...(copyRecipientsByEnvelope.get(envelope.id) ?? []),
      ].map((recipient) => recipient.email),
      status: envelope.status,
      statusLabel: buildDashboardStatusLabel(envelope, signers),
      title: envelope.title,
    };
  });
}

export async function getEnvelopeDetailDataForUser(
  userId: string,
  envelopeId: string,
  database: DbExecutor = getDb(),
): Promise<EnvelopeDetailData | null> {
  const envelope = await getEnvelopeByIdForUser(userId, envelopeId, database);

  if (!envelope) {
    return null;
  }

  const [signersByEnvelope, fieldsByEnvelope, auditEvents, copyRecipients] =
    await Promise.all([
      listSignersForEnvelopeIds([envelopeId], database),
      listFieldsForEnvelopeIds([envelopeId], database),
      listAuditEventsForEnvelope(envelopeId, database),
      listCopyRecipientsForEnvelopeId(envelopeId, database),
    ]);
  const signers = signersByEnvelope.get(envelopeId) ?? [];
  const fields = fieldsByEnvelope.get(envelopeId) ?? [];
  const fieldCountsBySigner = new Map(
    [...buildFieldsBySigner(fields)].map(
      ([signerId, signerFields]) =>
        [
          signerId,
          countAnswerableFields(signerFields, shouldCountFieldForSignerSummary),
        ] as const,
    ),
  );
  const timeline = auditEvents.map((event) => ({
    description: buildTimelineDescription(event),
    id: event.id,
    timestamp: formatTimelineTimestamp(event.createdAt),
    tone: TIMELINE_TONE_MAP[event.event],
  }));

  const signerViews = signers.map((signer, index) => {
    const previousSignerName = index > 0 ? signers[index - 1]?.name : undefined;
    const signerStatus: EnvelopeDetailSignerView["status"] =
      signer.status === "notified" ? "waiting" : signer.status;

    return {
      email: signer.email,
      id: signer.id,
      metaLabel: buildDetailSignerMetaLabel(
        envelope,
        signer,
        fieldCountsBySigner.get(signer.id) ?? 0,
      ),
      name: signer.name,
      order: signer.signOrder,
      status: signerStatus,
      statusDateLabel: buildDetailSignerStatusLabel(
        envelope,
        signer,
        previousSignerName,
      ),
    };
  });
  const currentSigner = signers.find((signer) => signer.status === "notified");
  let manualReminder: EnvelopeDetailManualReminderState | null = null;

  const nowUnixTimestamp = Math.floor(Date.now() / 1000);
  const expired = isEnvelopeExpired(envelope, nowUnixTimestamp);

  if (envelope.status === "sent" && currentSigner && expired) {
    // A reminder would carry a link that no longer works.
    manualReminder = { canSend: false, nextAvailableAtLabel: null };
  } else if (envelope.status === "sent" && currentSigner) {
    const nextAvailableAt =
      typeof currentSigner.lastNudgedAt === "number"
        ? getManualNudgeAvailableAt(currentSigner.lastNudgedAt)
        : null;
    const canSend = isManualNudgeAvailable(
      currentSigner.lastNudgedAt,
      nowUnixTimestamp,
    );

    manualReminder = {
      canSend,
      nextAvailableAtLabel:
        !canSend && typeof nextAvailableAt === "number"
          ? formatReminderAvailableAt(nextAvailableAt)
          : null,
    };
  }

  return {
    copyRecipients,
    createdAtLabel: formatLongDate(envelope.createdAt),
    deadline:
      envelope.status === "sent"
        ? {
            expired,
            expiresAtLabel:
              typeof envelope.expiresAt === "number"
                ? formatDeadline(envelope.expiresAt)
                : null,
          }
        : null,
    envelopeId,
    reminderIntervalDays:
      envelope.status === "sent"
        ? (envelope.reminderIntervalDays ?? null)
        : null,
    manualReminder,
    part11: Boolean(envelope.part11),
    signatureTypeLabel: describeSignatureType(envelope),
    signers: signerViews,
    status: envelope.status,
    timeline,
    title: envelope.title,
  };
}

export async function getDraftSignerStepDataForUser(
  userId: string,
  envelopeId: string,
  database: DbExecutor = getDb(),
): Promise<DraftSignerStepData | null> {
  const envelope = await getEnvelopeByIdForUser(userId, envelopeId, database);

  if (!envelope) {
    return null;
  }

  const checks = await listSignerCheckSettings(envelopeId, database);

  return {
    copyRecipients: await listCopyRecipientsForEnvelopeId(envelopeId, database),
    envelopeId,
    part11Mode: (await readStoredSettings(database))?.part11Mode ?? false,
    signers: (await listSignersForEnvelopeId(envelopeId, database)).map(
      (signer) => ({
        email: signer.email,
        hasAccessCode: checks.get(signer.id)?.hasAccessCode ?? false,
        id: signer.id,
        name: signer.name,
        order: signer.signOrder,
        requireEmailCode: checks.get(signer.id)?.requireEmailCode ?? false,
        signatureMeaning: checks.get(signer.id)?.signatureMeaning ?? null,
      }),
    ),
    status: envelope.status,
  };
}

export async function getDraftEnvelopeDocumentForUser(
  userId: string,
  envelopeId: string,
  {
    database = getDb(),
    storageService = createStorageService(),
  }: {
    database?: DbExecutor;
    storageService?: StorageService;
  } = {},
): Promise<DraftEnvelopeDocument> {
  const envelope = await getEnvelopeByIdForUser(userId, envelopeId, database);

  if (!envelope) {
    throw new EnvelopeDocumentAccessError("Envelope not found.", 404);
  }

  try {
    const object = await storageService.getObject(envelope.sourcePdfKey);

    return {
      body: object.body,
      contentLength: object.contentLength ?? object.body.length,
      contentType: object.contentType ?? "application/pdf",
      fileName: envelope.sourcePdfFilename,
    };
  } catch (error) {
    if (
      error instanceof StorageObjectNotFoundError ||
      (error instanceof Error &&
        (error.name === "NoSuchKey" || error.name === "NotFound"))
    ) {
      throw new EnvelopeDocumentAccessError("Source PDF is unavailable.", 404);
    }

    throw error;
  }
}

/**
 * Keeps the picture of the first page that the sender's browser drew. The
 * bytes are checked before they are stored: see services/thumbnails.ts.
 *
 * An envelope keeps the first picture it is given. Its document never
 * changes, so there is nothing a later picture could show that the first
 * does not, and a browser is told its copy is still good by the envelope
 * alone (buildThumbnailEtag), which only holds while the picture stays the
 * same.
 */
export async function saveEnvelopeThumbnailForUser(
  userId: string,
  envelopeId: string,
  body: Uint8Array,
  {
    database = getDb(),
    storageService = createStorageService(),
  }: {
    database?: DbExecutor;
    storageService?: StorageService;
  } = {},
): Promise<void> {
  assertThumbnailImage(body);

  const envelope = await getEnvelopeByIdForUser(userId, envelopeId, database);

  if (!envelope) {
    throw new EnvelopeDocumentAccessError("Envelope not found.", 404);
  }

  const key = buildEnvelopeThumbnailKey({
    envelopeId: envelope.id,
    sourcePdfKey: envelope.sourcePdfKey,
    userId,
  });

  await storageService.putObject({
    body,
    contentType: THUMBNAIL_CONTENT_TYPE,
    keepExisting: true,
    key,
  });

  // The envelope may have been deleted while the picture was being written:
  // by its owner, by the cleanup job or with the whole account. Each of
  // those removes the row first and the files after, so a row that is still
  // here now will have this picture removed with it. A row that is gone has
  // already had its files removed, and nothing would ever come back for this
  // one.
  const envelopeAfterWrite = await getEnvelopeByIdForUser(
    userId,
    envelopeId,
    database,
  );

  if (!envelopeAfterWrite) {
    await storageService.deleteObject(key);

    throw new EnvelopeDocumentAccessError("Envelope not found.", 404);
  }
}

export type EnvelopeThumbnail =
  | { etag: string; isNotModified: true }
  | { etag: string; isNotModified: false; picture: StorageObjectStream };

/**
 * Streams the stored first-page picture, or says there is none (404).
 *
 * A browser that already holds the picture sends the name it was given
 * (`ifNoneMatch`). The account is checked first, as always, and then the
 * answer is "your copy is still good" without a read from file storage.
 */
export async function getEnvelopeThumbnailForUser(
  userId: string,
  envelopeId: string,
  {
    database = getDb(),
    ifNoneMatch,
    storageService = createStorageService(),
  }: {
    database?: DbExecutor;
    ifNoneMatch?: string | null;
    storageService?: StorageService;
  } = {},
): Promise<EnvelopeThumbnail> {
  const envelope = await getEnvelopeByIdForUser(userId, envelopeId, database);

  if (!envelope) {
    throw new EnvelopeDocumentAccessError("Envelope not found.", 404);
  }

  const etag = buildThumbnailEtag(envelope.id);

  if (matchesEtag(ifNoneMatch, etag)) {
    return { etag, isNotModified: true };
  }

  try {
    const picture = await storageService.getObjectStream(
      buildEnvelopeThumbnailKey({
        envelopeId: envelope.id,
        sourcePdfKey: envelope.sourcePdfKey,
        userId,
      }),
    );

    return { etag, isNotModified: false, picture };
  } catch (error) {
    if (error instanceof StorageObjectNotFoundError) {
      throw new EnvelopeDocumentAccessError(
        "This document has no thumbnail yet.",
        404,
      );
    }

    throw error;
  }
}

export async function getPrepareEnvelopeDataForUser(
  userId: string,
  envelopeId: string,
  {
    database = getDb(),
  }: {
    database?: DbExecutor;
  } = {},
): Promise<PrepareEnvelopeData | null> {
  const envelope = await getEnvelopeByIdForUser(userId, envelopeId, database);

  if (!envelope) {
    return null;
  }

  const [fieldsByEnvelope, pages, signers] = await Promise.all([
    listFieldsForEnvelopeIds([envelopeId], database),
    listEnvelopePagesForEnvelopeId(envelopeId, database),
    listSignersForEnvelopeId(envelopeId, database),
  ]);

  return {
    envelopeId,
    fields: fieldsByEnvelope.get(envelopeId) ?? [],
    pageCount: envelope.pageCount,
    pages,
    pdfUrl: `/api/envelopes/${encodeURIComponent(envelopeId)}/document`,
    signers: signers.map((signer) => ({
      email: signer.email,
      id: signer.id,
      name: signer.name,
      order: signer.signOrder,
    })),
    status: envelope.status,
    title: envelope.title,
  };
}

export async function getReviewEnvelopeDataForUser(
  userId: string,
  envelopeId: string,
  database: DbExecutor = getDb(),
): Promise<ReviewEnvelopeData | null> {
  const envelope = await getEnvelopeByIdForUser(userId, envelopeId, database);

  if (!envelope) {
    return null;
  }

  const [signersByEnvelope, fieldsByEnvelope, copyRecipients] =
    await Promise.all([
      listSignersForEnvelopeIds([envelopeId], database),
      listFieldsForEnvelopeIds([envelopeId], database),
      listCopyRecipientsForEnvelopeId(envelopeId, database),
    ]);
  const signers = signersByEnvelope.get(envelopeId) ?? [];
  const fields = fieldsByEnvelope.get(envelopeId) ?? [];
  const fieldsBySigner = buildFieldsBySigner(fields);
  const missingSignatureSigner = getMissingSignatureSigner(
    signers,
    fieldsBySigner,
  );
  const isEmpty = signers.length === 0 || fields.length === 0;
  const choiceProblem = describeChoiceProblem(signers, fields);
  const provider = configuredSigningProvider();
  const part11Mode = provider
    ? ((await readStoredSettings(database))?.part11Mode ?? false)
    : false;

  return {
    canSend: !isEmpty && !missingSignatureSigner && !choiceProblem,
    signingProvider: provider && !part11Mode ? { name: provider.name } : null,
    copyRecipients,
    disabledReason: missingSignatureSigner
      ? `Every signer must have at least one Signature field before sending. ${missingSignatureSigner.name} is missing one.`
      : choiceProblem,
    envelopeId,
    filename: envelope.sourcePdfFilename,
    isEmpty,
    pageCount: envelope.pageCount,
    signers: signers.map((signer) => ({
      email: signer.email,
      fieldSummaries: withRadioGroupsOnce(fieldsBySigner.get(signer.id) ?? [])
        .sort(
          (left, right) =>
            FIELD_TYPE_SORT_ORDER[left.type] -
            FIELD_TYPE_SORT_ORDER[right.type],
        )
        .map((field) => FIELD_TYPE_SUMMARY_LABELS[field.type]),
      id: signer.id,
      name: signer.name,
      order: signer.signOrder,
    })),
    sizeLabel: formatFileSize(envelope.sourcePdfSizeBytes),
    status: envelope.status,
    title: envelope.title,
  };
}

/** Everyone on a draft and every field placed for them, in a fixed order. */
async function readDraftParties(envelopeId: string, database: DbExecutor) {
  const signers = await listSignersForEnvelopeId(envelopeId, database);
  const fields =
    (await listFieldsForEnvelopeIds([envelopeId], database)).get(envelopeId) ??
    [];
  const copyRecipients = await listCopyRecipientsForEnvelopeId(
    envelopeId,
    database,
  );

  return { copyRecipients, fields, signers };
}

/**
 * Takes hold of a draft before its signers or fields are changed, and
 * refuses when it is no longer a draft. Saving signers, saving fields,
 * sending, and erasing a signer on request all take the envelope's row
 * first, so they happen one after the other: a save cannot land on an
 * envelope that was sent a moment before, and a send cannot go out with
 * signers or fields that a save or an erasure was just then replacing.
 *
 * The lock an UPDATE takes, not FOR UPDATE: the signer rows written next
 * need a share of this row for their foreign key.
 */
async function lockDraftEnvelope(
  userId: string,
  envelopeId: string,
  tx: DbExecutor,
): Promise<void> {
  const locked = await tx.query(
    `
      SELECT id FROM envelopes
      WHERE id = $1 AND user_id = $2 AND status = 'draft'
      FOR NO KEY UPDATE
    `,
    [envelopeId, userId],
  );

  if (locked.rowCount !== 1) {
    throw new EnvelopeMutationError(
      "Only draft envelopes can be updated.",
      409,
    );
  }
}

export async function sendDraftEnvelope(
  userId: string,
  envelopeId: string,
  input: SendDraftEnvelopeInput,
  { database = getDb() }: SendDraftEnvelopeOptions = {},
): Promise<SendDraftEnvelopeResult> {
  const envelope = await getEnvelopeByIdForUser(userId, envelopeId, database);

  if (!envelope) {
    throw new EnvelopeMutationError("Envelope not found.", 404);
  }

  if (envelope.status !== "draft") {
    throw new EnvelopeMutationError("Only draft envelopes can be sent.", 409);
  }

  const checkedParties = await readDraftParties(envelopeId, database);
  const { fields, signers } = checkedParties;

  if (signers.length === 0 || fields.length === 0) {
    throw new EnvelopeMutationError(
      "Add signers and place fields before sending this envelope.",
      400,
    );
  }

  const signerIds = new Set(signers.map((signer) => signer.id));

  if (fields.some((field) => !signerIds.has(field.signerId))) {
    throw new EnvelopeMutationError(
      "Each field must be assigned to an existing signer on this envelope.",
      400,
    );
  }

  const missingSignatureSigner = getMissingSignatureSigner(
    signers,
    buildFieldsBySigner(fields),
  );

  if (missingSignatureSigner) {
    throw new EnvelopeMutationError(
      `Every signer must have at least one Signature field before sending. ${missingSignatureSigner.name} is missing one.`,
      400,
    );
  }

  const choiceProblem = describeChoiceProblem(signers, fields);

  if (choiceProblem) {
    throw new EnvelopeMutationError(choiceProblem, 400);
  }

  // In Part 11 mode each signer signs with their own verified account, and
  // the envelope keeps that rule even if the mode is turned off later.
  const part11 = (await readStoredSettings(database))?.part11Mode ?? false;

  // Signatures in the signers' own names need the install's signing
  // provider. Part 11 envelopes are signed with the signers' accounts, and
  // the two are not combined.
  const signatureLevel = input.signatureLevel ?? "simple";
  const signingProvider =
    signatureLevel === "simple" ? null : configuredSigningProvider();

  if (signatureLevel !== "simple") {
    if (!signingProvider) {
      throw new EnvelopeMutationError(
        "This install has no signing provider for advanced or qualified signatures.",
        400,
      );
    }

    if (part11) {
      throw new EnvelopeMutationError(
        "Part 11 mode signs with the signers' accounts. Send with simple signatures.",
        400,
      );
    }
  }

  const part11SignerAccounts = new Map<string, string>();

  if (part11) {
    const checks = await listSignerCheckSettings(envelopeId, database);
    const accounts = await findSignerAccounts(
      signers.map((signer) => signer.email),
      database,
    );

    for (const signer of signers) {
      const account = accounts.get(signer.email.toLowerCase());
      const problem = describePart11SignerProblem(
        {
          email: signer.email,
          name: signer.name,
          signatureMeaning: checks.get(signer.id)?.signatureMeaning ?? null,
        },
        account,
      );

      if (problem || !account) {
        throw new EnvelopeMutationError(
          problem ?? "A signer cannot sign in Part 11 mode.",
          400,
        );
      }

      part11SignerAccounts.set(signer.id, account.userId);
    }
  }

  const firstSigner = signers[0];

  if (!firstSigner) {
    throw new EnvelopeMutationError(
      "Add signers before sending this envelope.",
      400,
    );
  }

  const emailService = createEmailService();
  const storageService = createStorageService();
  const sourcePdfHead = await storageService.headObject(envelope.sourcePdfKey);

  if (!sourcePdfHead.exists) {
    throw new EnvelopeMutationError(
      "The source document for this envelope could not be found.",
      500,
    );
  }

  const sentAt = Math.floor(Date.now() / 1000);
  const sentAuditAt = Math.max(sentAt, envelope.createdAt + 1);
  const expiresAt = deadlineFromDays(sentAt, input.expiresInDays);
  const issuedLink = await issueSigningLink({
    expiresInSeconds: expiresAt - sentAt,
    issuedAt: sentAt,
  });

  try {
    await withTransaction(async (tx) => {
      const updatedEnvelope = await tx.query(
        `
          UPDATE envelopes
          SET
            status = 'sent',
            sent_at = $1,
            updated_at = $2,
            expires_at = $5,
            expiry_notified_at = NULL,
            reminder_interval_days = $6
          WHERE id = $3
            AND user_id = $4
            AND status = 'draft'
        `,
        [
          sentAt,
          sentAt,
          envelopeId,
          userId,
          expiresAt,
          input.reminderIntervalDays ?? null,
        ],
      );

      if (updatedEnvelope.rowCount !== 1) {
        throw new EnvelopeMutationError(
          "This envelope has already been sent.",
          409,
        );
      }

      // The signers and fields were read and checked before this
      // transaction began. The update above holds the envelope's row,
      // which everything that changes a draft's signers or fields takes
      // first, so what is read here is what goes out. If it is not what
      // was checked (a signer erased on request, a save from another tab),
      // nothing is sent.
      if (
        JSON.stringify(await readDraftParties(envelopeId, tx)) !==
        JSON.stringify(checkedParties)
      ) {
        throw new EnvelopeMutationError(
          "This envelope was changed while it was being sent. Check it and send it again.",
          409,
        );
      }

      await tx.query(
        `
          UPDATE signers
          SET
            status = 'pending',
            signing_token_hash = NULL,
            signing_token_expires_at = NULL,
            turn_started_at = NULL,
            last_notified_at = NULL,
            last_nudged_at = NULL,
            signed_at = NULL,
            declined_at = NULL,
            decline_reason = NULL,
            user_id = NULL,
            updated_at = $1
          WHERE envelope_id = $2
        `,
        [sentAt, envelopeId],
      );

      if (signingProvider) {
        await tx.query(
          `
            UPDATE envelopes
            SET signature_level = $1, signature_provider = $2
            WHERE id = $3
          `,
          [signatureLevel, signingProvider.id, envelopeId],
        );
      }

      if (part11) {
        await tx.query(`UPDATE envelopes SET part11 = true WHERE id = $1`, [
          envelopeId,
        ]);

        for (const [signerId, accountId] of part11SignerAccounts) {
          const bound = await tx.query(
            `
              UPDATE signers
              SET user_id = $1
              WHERE id = $2
                AND envelope_id = $3
                AND signature_meaning IS NOT NULL
            `,
            [accountId, signerId, envelopeId],
          );

          if (bound.rowCount !== 1) {
            throw new EnvelopeMutationError(
              "This envelope was changed while it was being sent. Check it and send it again.",
              409,
            );
          }
        }
      }

      const updatedSigner = await tx.query(
        `
          UPDATE signers
          SET
            status = 'notified',
            signing_token_hash = $1,
            signing_token_expires_at = $2,
            turn_started_at = $3,
            last_notified_at = $4,
            updated_at = $5
          WHERE id = $6
            AND envelope_id = $7
        `,
        [
          issuedLink.tokenHash,
          issuedLink.exp,
          sentAt,
          sentAt,
          sentAt,
          firstSigner.id,
          envelopeId,
        ],
      );

      if (updatedSigner.rowCount !== 1) {
        throw new EnvelopeMutationError(
          "Unable to activate the first signer for this envelope.",
          500,
        );
      }

      await recordAuditEvent(
        {
          actorEmail: input.senderEmail,
          actorType: "sender",
          createdAt: sentAuditAt,
          envelopeId,
          event: "sent",
          ipAddress: input.ipAddress ?? null,
          metadata: {
            // The send route refuses a send without this confirmation.
            expiresAt,
            reminderIntervalDays: input.reminderIntervalDays ?? null,
            permittedUseConfirmed: true,
            permittedUseVersion: PERMITTED_USE_VERSION,
            ...(part11 ? { part11: true } : {}),
            ...(signingProvider
              ? {
                  signatureLevel,
                  signingProvider: signingProvider.name,
                }
              : {}),
            signerEmail: firstSigner.email,
            signerId: firstSigner.id,
            signerName: firstSigner.name,
          },
          userAgent: input.userAgent ?? null,
        },
        tx,
      );
    }, database);
  } catch (error) {
    throw error;
  }

  let invitationMessageId: string | undefined;

  try {
    invitationMessageId = (
      await emailService.send(
        buildSigningInvitationEmail({
          branding: await getBranding(),
          envelopeTitle: envelope.title,
          expiresAt,
          senderName: input.senderName,
          signerEmail: firstSigner.email,
          signerName: firstSigner.name,
          signingUrl: issuedLink.url,
        }),
      )
    ).messageId;
  } catch (error) {
    await withTransaction(async (tx) => {
      await tx.query(
        `
          UPDATE envelopes
          SET
            status = 'draft',
            sent_at = NULL,
            expires_at = NULL,
            reminder_interval_days = NULL,
            part11 = false,
            signature_level = 'simple',
            signature_provider = NULL,
            updated_at = $1
          WHERE id = $2
            AND user_id = $3
            AND status = 'sent'
        `,
        [envelope.updatedAt, envelopeId, userId],
      );

      await tx.query(
        `
          UPDATE signers
          SET
            status = 'pending',
            signing_token_hash = NULL,
            signing_token_expires_at = NULL,
            turn_started_at = NULL,
            last_notified_at = NULL,
            last_nudged_at = NULL,
            signed_at = NULL,
            declined_at = NULL,
            decline_reason = NULL,
            user_id = NULL,
            updated_at = $1
          WHERE envelope_id = $2
        `,
        [envelope.updatedAt, envelopeId],
      );

      await lockEnvelopeAuditChain(envelopeId, tx);
      await tx.query(
        `
          DELETE FROM audit_events
          WHERE envelope_id = $1
            AND event = 'sent'
            AND created_at = $2
            AND actor_email = $3
            -- Only while it is still the newest link of the audit chain: an
            -- event recorded after it (say, the invitation was opened before
            -- the send failed) chains to it, so it stays as history.
            AND sequence = (
              SELECT max(sequence) FROM audit_events WHERE envelope_id = $1
            )
        `,
        [envelopeId, sentAuditAt, input.senderEmail],
      );
    }, database).catch((rollbackError) => {
      console.error(
        `Failed to roll back sent envelope ${envelopeId} after email delivery failure:`,
        rollbackError,
      );
    });

    throw error;
  }

  await recordEmailSent(
    {
      envelopeId,
      messageId: invitationMessageId,
      recipient: firstSigner.email,
      signerId: firstSigner.id,
      template: "signing_invitation",
    },
    database,
  );

  return sendEnvelopeResponseSchema.parse({
    envelopeId,
    expiresAt,
    notifiedSignerName: firstSigner.name,
    redirectPath: `/envelopes/${envelopeId}`,
    sentAt,
  });
}

type ChangeEnvelopeDeadlineInput = {
  expiresInDays: number;
  ipAddress?: string | null;
  senderEmail: string;
  userAgent?: string | null;
};

/**
 * Gives an envelope that is out for signature a new deadline, counted from
 * now. The current signer's link is kept and simply lives until the new
 * deadline, so a link that had expired works again.
 */
export async function changeEnvelopeDeadline(
  userId: string,
  envelopeId: string,
  input: ChangeEnvelopeDeadlineInput,
  {
    database = getDb(),
    nowUnixTimestamp = Math.floor(Date.now() / 1000),
  }: { database?: DbPool; nowUnixTimestamp?: number } = {},
): Promise<ChangeDeadlineResponse> {
  const expiresAt = deadlineFromDays(nowUnixTimestamp, input.expiresInDays);

  await withTransaction(async (tx) => {
    const current = await queryOne<{
      expiresAt: number | null;
      status: EnvelopeRecord["status"];
    }>(
      tx,
      `
        SELECT expires_at AS "expiresAt", status
        FROM envelopes
        WHERE id = $1 AND user_id = $2
        -- The lock an UPDATE takes, not FOR UPDATE: storing an audit event
        -- needs a share of this row for its foreign key, and FOR UPDATE
        -- would deadlock with a signer opening the signing page.
        FOR NO KEY UPDATE
      `,
      [envelopeId, userId],
    );

    if (!current) {
      throw new EnvelopeMutationError("Envelope not found.", 404);
    }

    if (current.status !== "sent") {
      throw new EnvelopeMutationError(
        "Only an envelope that is out for signature has a deadline to change.",
        409,
      );
    }

    await tx.query(
      `
        UPDATE envelopes
        SET expires_at = $1, expiry_notified_at = NULL, updated_at = $2
        WHERE id = $3
      `,
      [expiresAt, nowUnixTimestamp, envelopeId],
    );
    await tx.query(
      `
        UPDATE signers
        SET signing_token_expires_at = $1, updated_at = $2
        WHERE envelope_id = $3
          AND status = 'notified'
          AND signing_token_hash IS NOT NULL
      `,
      [expiresAt, nowUnixTimestamp, envelopeId],
    );
    await recordAuditEvent(
      {
        actorEmail: input.senderEmail,
        actorType: "sender",
        createdAt: nowUnixTimestamp,
        envelopeId,
        event: "deadline_changed",
        ipAddress: input.ipAddress ?? null,
        metadata: { expiresAt, previousExpiresAt: current.expiresAt },
        userAgent: input.userAgent ?? null,
      },
      tx,
    );
  }, database);

  return changeDeadlineResponseSchema.parse({
    envelopeId,
    expiresAt,
    expiresAtLabel: formatDeadline(expiresAt),
  });
}

const SENT_ENVELOPE_SIGNER_CORRECTION_MESSAGE =
  "Only an envelope that is out for signature can have a signer corrected.";

/**
 * Fixes the name and/or email of a signer who has not signed or declined on
 * an envelope that is out for signature. The signing link they already have
 * stops working. If it is their turn, a new invitation goes to the
 * corrected address.
 *
 * The envelope and signer rows stay locked until that invitation is sent
 * or refused, so another correction of the same person waits. A failed
 * send rolls the whole transaction back: the last committed identity
 * returns, the original link still works when nothing succeeded, and no
 * signer_corrected event is left behind. The audit event is written in
 * this same transaction after a successful send, so overlapping
 * corrections cannot appear out of order.
 */
export async function correctSentEnvelopeSigner(
  userId: string,
  envelopeId: string,
  signerId: string,
  input: unknown,
  context: CorrectSentEnvelopeSignerContext,
  {
    database = getDb(),
    emailService,
    nowUnixTimestamp = Math.floor(Date.now() / 1000),
  }: CorrectSentEnvelopeSignerOptions = {},
): Promise<CorrectSentSignerResult> {
  const parsedInput = correctSentSignerSchema.parse(input);

  return withTransaction(async (tx) => {
    const envelope = await queryOne<{
      expiresAt: number | null;
      part11: boolean;
      status: EnvelopeRecord["status"];
      title: string;
      updatedAt: number;
      userId: string;
    }>(
      tx,
      `
        SELECT
          expires_at AS "expiresAt",
          part11,
          status,
          title,
          updated_at AS "updatedAt",
          user_id AS "userId"
        FROM envelopes
        WHERE id = $1 AND user_id = $2
        FOR NO KEY UPDATE
      `,
      [envelopeId, userId],
    );

    if (!envelope) {
      throw new EnvelopeMutationError("Envelope not found.", 404);
    }

    if (envelope.status !== "sent") {
      throw new EnvelopeMutationError(
        SENT_ENVELOPE_SIGNER_CORRECTION_MESSAGE,
        409,
      );
    }

    if (envelope.part11) {
      throw new EnvelopeMutationError(
        "This envelope was sent in Part 11 mode. The signer's identity is bound to their account and cannot be corrected.",
        409,
      );
    }

    const signer = await queryOne<{
      consentedAt: number | null;
      email: string;
      emailCodeAttempts: number;
      emailCodeExpiresAt: number | null;
      emailCodeHash: string | null;
      emailCodeSentAt: number | null;
      lastNotifiedAt: number | null;
      name: string;
      role: string;
      signOrder: number;
      signingTokenExpiresAt: number | null;
      signingTokenHash: string | null;
      status: SignerRecord["status"];
      updatedAt: number;
    }>(
      tx,
      `
        SELECT
          consented_at AS "consentedAt",
          email,
          email_code_attempts AS "emailCodeAttempts",
          email_code_expires_at AS "emailCodeExpiresAt",
          email_code_hash AS "emailCodeHash",
          email_code_sent_at AS "emailCodeSentAt",
          last_notified_at AS "lastNotifiedAt",
          name,
          role,
          sign_order AS "signOrder",
          signing_token_expires_at AS "signingTokenExpiresAt",
          signing_token_hash AS "signingTokenHash",
          status,
          updated_at AS "updatedAt"
        FROM signers
        WHERE id = $1 AND envelope_id = $2
        FOR NO KEY UPDATE
      `,
      [signerId, envelopeId],
    );

    if (!signer || signer.role !== "signer") {
      throw new EnvelopeMutationError("Envelope not found.", 404);
    }

    if (signer.status === "signed") {
      throw new EnvelopeMutationError(
        "This person has already signed and cannot be corrected.",
        409,
      );
    }

    if (signer.status === "declined") {
      throw new EnvelopeMutationError(
        "This person has already declined and cannot be corrected.",
        409,
      );
    }

    const nextName = parsedInput.name ?? signer.name;
    const nextEmail = parsedInput.email ?? signer.email;

    if (
      nextName === signer.name &&
      nextEmail.toLowerCase() === signer.email.toLowerCase()
    ) {
      return correctSentSignerResponseSchema.parse({
        email: signer.email,
        envelopeId,
        invitationSent: false,
        name: signer.name,
        signerId,
      });
    }

    const duplicate = await queryOne<{ id: string; role: string }>(
      tx,
      `
        SELECT id, role
        FROM signers
        WHERE envelope_id = $1
          AND lower(email) = $2
          AND id <> $3
      `,
      [envelopeId, nextEmail.toLowerCase(), signerId],
    );

    if (duplicate) {
      throw new EnvelopeMutationError(
        duplicate.role === "cc"
          ? duplicateCopyRecipientEmailMessage
          : duplicateSignerEmailMessage,
        400,
      );
    }

    let issuedLink: IssuedSigningLink | null = null;
    let tokenHash: string | null = null;
    let tokenExpiresAt: number | null = null;
    let lastNotifiedAt = signer.lastNotifiedAt;
    const invitationNeeded = signer.status === "notified";

    if (invitationNeeded) {
      const remainingSeconds =
        typeof envelope.expiresAt === "number" &&
        envelope.expiresAt > nowUnixTimestamp
          ? envelope.expiresAt - nowUnixTimestamp
          : typeof envelope.expiresAt === "number"
            ? 1
            : signingLinkLifetimeSeconds(envelope.expiresAt, nowUnixTimestamp);

      issuedLink = await issueSigningLink({
        expiresInSeconds: remainingSeconds,
        issuedAt: nowUnixTimestamp,
      });
      tokenHash = issuedLink.tokenHash;
      tokenExpiresAt =
        typeof envelope.expiresAt === "number"
          ? envelope.expiresAt
          : issuedLink.exp;
      lastNotifiedAt = nowUnixTimestamp;
    }

    const updatedSigner = await tx.query(
      `
        UPDATE signers
        SET
          name = $1,
          email = $2,
          signing_token_hash = $3,
          signing_token_expires_at = $4,
          last_notified_at = $5,
          consented_at = NULL,
          email_code_hash = NULL,
          email_code_expires_at = NULL,
          email_code_attempts = 0,
          email_code_sent_at = NULL,
          updated_at = $6
        WHERE id = $7
          AND envelope_id = $8
          AND status IN ('pending', 'notified')
      `,
      [
        nextName,
        nextEmail,
        tokenHash,
        tokenExpiresAt,
        lastNotifiedAt,
        nowUnixTimestamp,
        signerId,
        envelopeId,
      ],
    );

    if (updatedSigner.rowCount !== 1) {
      throw new EnvelopeMutationError(
        "This person has already signed or declined and cannot be corrected.",
        409,
      );
    }

    await tx.query(
      `
        UPDATE envelopes
        SET updated_at = $1
        WHERE id = $2
      `,
      [nowUnixTimestamp, envelopeId],
    );

    if (invitationNeeded && issuedLink) {
      const mailer = emailService ?? createEmailService();
      const invitationMessageId = (
        await mailer.send(
          buildSigningInvitationEmail({
            branding: await getBranding(),
            envelopeTitle: envelope.title,
            expiresAt: envelope.expiresAt,
            senderName: context.senderName,
            signerEmail: nextEmail,
            signerName: nextName,
            signingUrl: issuedLink.url,
          }),
        )
      ).messageId;

      await recordAuditEvent(
        {
          actorEmail: context.senderEmail,
          actorType: "sender",
          createdAt: nowUnixTimestamp,
          envelopeId,
          event: "signer_corrected",
          ipAddress: context.ipAddress ?? null,
          metadata: {
            previousEmail: signer.email,
            previousName: signer.name,
            signerEmail: nextEmail,
            signerId,
            signerName: nextName,
            signerOrder: signer.signOrder,
          },
          userAgent: context.userAgent ?? null,
        },
        tx,
      );
      await recordEmailSent(
        {
          envelopeId,
          messageId: invitationMessageId,
          recipient: nextEmail,
          signerId,
          template: "signing_invitation",
        },
        tx,
      );

      return correctSentSignerResponseSchema.parse({
        email: nextEmail,
        envelopeId,
        invitationSent: true,
        name: nextName,
        signerId,
      });
    }

    await recordAuditEvent(
      {
        actorEmail: context.senderEmail,
        actorType: "sender",
        createdAt: nowUnixTimestamp,
        envelopeId,
        event: "signer_corrected",
        ipAddress: context.ipAddress ?? null,
        metadata: {
          previousEmail: signer.email,
          previousName: signer.name,
          signerEmail: nextEmail,
          signerId,
          signerName: nextName,
          signerOrder: signer.signOrder,
        },
        userAgent: context.userAgent ?? null,
      },
      tx,
    );

    return correctSentSignerResponseSchema.parse({
      email: nextEmail,
      envelopeId,
      invitationSent: false,
      name: nextName,
      signerId,
    });
  }, database);
}

/**
 * Turns automatic reminders on, off, or to another interval for an envelope
 * that is out for signature. The interval counts from the last time the
 * signer was written to, so turning them on can send one the next day.
 */
export async function changeEnvelopeReminders(
  userId: string,
  envelopeId: string,
  reminderIntervalDays: number | null,
  {
    database = getDb(),
    nowUnixTimestamp = Math.floor(Date.now() / 1000),
  }: { database?: DbExecutor; nowUnixTimestamp?: number } = {},
): Promise<ChangeRemindersResponse> {
  const updated = await database.query(
    `
      UPDATE envelopes
      SET reminder_interval_days = $1, updated_at = $2
      WHERE id = $3 AND user_id = $4 AND status = 'sent'
    `,
    [reminderIntervalDays, nowUnixTimestamp, envelopeId, userId],
  );

  if (updated.rowCount !== 1) {
    const envelope = await getEnvelopeByIdForUser(userId, envelopeId, database);

    throw envelope
      ? new EnvelopeMutationError(
          "Reminders can only be changed while an envelope is out for signature.",
          409,
        )
      : new EnvelopeMutationError("Envelope not found.", 404);
  }

  return changeRemindersResponseSchema.parse({
    envelopeId,
    reminderIntervalDays,
  });
}

export async function voidSentEnvelope(
  userId: string,
  envelopeId: string,
  input: VoidEnvelopeInput,
  { database = getDb() }: VoidEnvelopeOptions = {},
): Promise<VoidEnvelopeResult> {
  const envelope = await getEnvelopeByIdForUser(userId, envelopeId, database);

  if (!envelope) {
    throw new EnvelopeMutationError("Envelope not found.", 404);
  }

  if (envelope.status !== "sent") {
    throw new EnvelopeMutationError("Only sent envelopes can be voided.", 409);
  }

  const reason = input.reason?.trim().slice(0, 1000) || null;

  if (envelope.part11 && !reason) {
    throw new EnvelopeMutationError(
      "Give a reason for voiding. Part 11 records keep it in the audit trail.",
      400,
    );
  }

  const signers = await listSignersForEnvelopeId(envelopeId, database);
  const notifiedSigners = signers.filter(
    (signer) => signer.status === "notified",
  );
  const currentSigner = notifiedSigners[0];
  const voidedAt = Math.floor(Date.now() / 1000);
  const emailService = createEmailService();
  const storageService = createStorageService();
  const sourcePdfHead = await storageService.headObject(envelope.sourcePdfKey);

  if (!sourcePdfHead.exists) {
    throw new EnvelopeMutationError(
      "The source document for this envelope could not be found.",
      500,
    );
  }

  const voidedAuditEvent: AuditEventRecord = {
    actorEmail: input.senderEmail,
    actorType: "sender",
    createdAt: voidedAt,
    envelopeId,
    event: "voided",
    id: randomUUID(),
    ipAddress: input.ipAddress ?? null,
    metadata:
      currentSigner || reason
        ? {
            ...(currentSigner
              ? {
                  signerEmail: currentSigner.email,
                  signerId: currentSigner.id,
                  signerName: currentSigner.name,
                  signerOrder: currentSigner.signOrder,
                }
              : {}),
            ...(reason ? { reason } : {}),
          }
        : null,
    userAgent: input.userAgent ?? null,
  };
  const storageIdentity = {
    envelopeId,
    userId,
  };
  const canonicalCertificate = {
    bucketName: sourcePdfHead.bucketName,
    key: buildEnvelopeCertificateKey({
      ...storageIdentity,
      audience: "internal",
    }),
  };
  const voidedEnvelope = envelopeRecordSchema.parse({
    ...envelope,
    evidenceKey: canonicalCertificate.key,
    status: "voided",
    updatedAt: voidedAt,
    voidedAt,
  });
  const voidedSigners = signers.map((signer) =>
    signer.status === "notified"
      ? signerRecordSchema.parse({
          ...signer,
          signingTokenExpiresAt: null,
          signingTokenHash: null,
          updatedAt: voidedAt,
        })
      : signer,
  );
  const auditEvents = [
    ...(await listAuditEventsForEnvelope(envelopeId, database)),
    voidedAuditEvent,
  ];
  const storedCertificateKeys: string[] = [];
  let certificate: { key: string; sha256: string };
  let recipientCertificateSha256: string;

  try {
    certificate = await storeEnvelopeCertificatePdf(
      {
        auditEvents,
        certificate: canonicalCertificate,
        envelope: voidedEnvelope,
        signers: voidedSigners,
      },
      {
        storageService,
      },
    );
    storedCertificateKeys.push(certificate.key);

    const recipientCertificate = await storeRecipientEnvelopeCertificatePdf(
      {
        auditEvents,
        certificate: {
          bucketName: sourcePdfHead.bucketName,
          key: buildEnvelopeCertificateKey({
            ...storageIdentity,
            audience: "recipient",
          }),
        },
        envelope: voidedEnvelope,
        signers: voidedSigners,
      },
      {
        storageService,
      },
    );
    storedCertificateKeys.push(recipientCertificate.key);
    recipientCertificateSha256 = recipientCertificate.sha256;
  } catch (error) {
    await Promise.all(
      storedCertificateKeys.map((key) =>
        storageService.deleteObject(key).catch(() => undefined),
      ),
    );
    throw error;
  }

  try {
    await withTransaction(async (tx) => {
      const persistedEnvelope = await getEnvelopeByIdForUser(
        userId,
        envelopeId,
        tx,
      );

      if (!persistedEnvelope) {
        throw new EnvelopeMutationError("Envelope not found.", 404);
      }

      if (persistedEnvelope.status !== "sent") {
        throw new EnvelopeMutationError(
          "Only sent envelopes can be voided.",
          409,
        );
      }

      const updatedEnvelope = await tx.query(
        `
          UPDATE envelopes
          SET
            status = 'voided',
            evidence_key = $1,
            voided_at = $2,
            updated_at = $3,
            evidence_sha256 = $6,
            recipient_evidence_sha256 = $7
          WHERE id = $4
            AND user_id = $5
            AND status = 'sent'
        `,
        [
          certificate.key,
          voidedAt,
          voidedAt,
          envelopeId,
          userId,
          certificate.sha256,
          recipientCertificateSha256,
        ],
      );

      if (updatedEnvelope.rowCount !== 1) {
        throw new EnvelopeMutationError(
          "This envelope can no longer be voided.",
          409,
        );
      }

      await tx.query(
        `
          UPDATE signers
          SET
            signing_token_hash = NULL,
            signing_token_expires_at = NULL,
            updated_at = $1
          WHERE envelope_id = $2
            AND status = 'notified'
        `,
        [voidedAt, envelopeId],
      );

      await recordAuditEvent(
        {
          actorEmail: voidedAuditEvent.actorEmail,
          actorType: voidedAuditEvent.actorType,
          id: voidedAuditEvent.id,
          createdAt: voidedAuditEvent.createdAt,
          envelopeId: voidedAuditEvent.envelopeId,
          event: voidedAuditEvent.event,
          ipAddress: voidedAuditEvent.ipAddress,
          metadata: voidedAuditEvent.metadata,
          userAgent: voidedAuditEvent.userAgent,
        },
        tx,
      );
    }, database);
  } catch (error) {
    await Promise.all(
      storedCertificateKeys.map((key) =>
        storageService.deleteObject(key).catch(() => undefined),
      ),
    );
    throw error;
  }

  const branding = await getBranding().catch(() => null);

  await Promise.all(
    notifiedSigners.map(async (signer) => {
      try {
        if (!branding) {
          throw new Error(
            "Could not load settings for the notification email.",
          );
        }

        const delivery = await emailService.send(
          buildVoidNotificationEmail({
            branding,
            envelopeId,
            envelopeTitle: envelope.title,
            senderName: input.senderName,
            signerEmail: signer.email,
            signerName: signer.name,
          }),
        );

        await recordEmailSent(
          {
            envelopeId,
            messageId: delivery.messageId,
            recipient: signer.email,
            signerId: signer.id,
            template: "void_notification",
          },
          database,
        );
      } catch (error) {
        console.error(
          `Failed to send void notification for envelope ${envelopeId} to ${signer.email}:`,
          error,
        );
      }
    }),
  );

  return voidEnvelopeResponseSchema.parse({
    envelopeId,
    redirectPath: `/envelopes/${envelopeId}`,
    voidedAt,
  });
}

export async function replaceDraftEnvelopeFields(
  userId: string,
  envelopeId: string,
  input: unknown,
  database: DbPool = getDb(),
): Promise<ReplaceDraftFieldsResult> {
  const parsedInput = replaceFieldsSchema.parse(input);
  const envelope = await getEnvelopeByIdForUser(userId, envelopeId, database);

  if (!envelope) {
    throw new EnvelopeMutationError("Envelope not found.", 404);
  }

  if (envelope.status !== "draft") {
    throw new EnvelopeMutationError(
      "Only draft envelopes can be updated.",
      409,
    );
  }

  const [signers, pages, existingFieldsByEnvelope] = await Promise.all([
    listSignersForEnvelopeId(envelopeId, database),
    listEnvelopePagesForEnvelopeId(envelopeId, database),
    listFieldsForEnvelopeIds([envelopeId], database),
  ]);
  const signerIds = new Set(signers.map((signer) => signer.id));
  const pageNumbers = new Set(pages.map((page) => page.pageNumber));
  const existingFields = existingFieldsByEnvelope.get(envelopeId) ?? [];
  const existingFieldMetadata = new Map(
    existingFields.map((field) => [field.id, field.createdAt] as const),
  );
  const usedFieldIds = new Set<string>();
  const updatedAt = Math.floor(Date.now() / 1000);
  const nextFields = parsedInput.fields.map((field, index) => {
    const parsedField = fieldPlacementSchema.parse(field);

    if (!signerIds.has(parsedField.signerId)) {
      throw new EnvelopeMutationError(
        "Each field must be assigned to an existing signer on this envelope.",
        400,
      );
    }

    if (!pageNumbers.has(parsedField.page)) {
      throw new EnvelopeMutationError(
        "Each field must be placed on an existing page in this document.",
        400,
      );
    }

    const fieldId = parsedField.id ?? randomUUID();

    if (usedFieldIds.has(fieldId)) {
      throw new EnvelopeMutationError("Each field must be unique.", 400);
    }

    usedFieldIds.add(fieldId);

    return {
      ...parsedField,
      createdAt: existingFieldMetadata.get(fieldId) ?? updatedAt + index,
      id: fieldId,
      updatedAt,
    };
  });

  await withTransaction(async (tx) => {
    await lockDraftEnvelope(userId, envelopeId, tx);
    await tx.query(
      `
        DELETE FROM fields
        WHERE envelope_id = $1
      `,
      [envelopeId],
    );

    for (const field of nextFields) {
      await tx.query(
        `
          INSERT INTO fields (
            id,
            envelope_id,
            signer_id,
            type,
            page,
            x,
            y,
            width,
            height,
            required,
            label,
            input_method,
            value,
            image_key,
            checked,
            submitted_at,
            created_at,
            updated_at,
            options,
            group_id
          ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NULL, NULL, NULL, NULL, NULL, $12, $13, $14::jsonb, $15
          )
        `,
        [
          field.id,
          envelopeId,
          field.signerId,
          field.type,
          field.page,
          field.x,
          field.y,
          field.width,
          field.height,
          field.required,
          field.label ?? null,
          field.createdAt,
          field.updatedAt,
          field.type === "dropdown"
            ? JSON.stringify(field.options ?? [])
            : null,
          field.groupId ?? null,
        ],
      );
    }

    await tx.query(
      `
        UPDATE envelopes
        SET updated_at = $1
        WHERE id = $2 AND user_id = $3
      `,
      [updatedAt, envelopeId, userId],
    );
  }, database);

  return replaceFieldsResponseSchema.parse({
    envelopeId,
    fields:
      (await listFieldsForEnvelopeIds([envelopeId], database)).get(
        envelopeId,
      ) ?? [],
    redirectPath: `/envelopes/${envelopeId}/review`,
    updatedAt,
  }) as ReplaceDraftFieldsResult;
}

export async function replaceDraftEnvelopeSigners(
  userId: string,
  envelopeId: string,
  input: unknown,
  database: DbPool = getDb(),
): Promise<ReplaceDraftSignersResult> {
  const parsedInput = replaceSignersSchema.parse(input);
  const envelope = await getEnvelopeByIdForUser(userId, envelopeId, database);

  if (!envelope) {
    throw new EnvelopeMutationError("Envelope not found.", 404);
  }

  if (envelope.status !== "draft") {
    throw new EnvelopeMutationError(
      "Only draft envelopes can be updated.",
      409,
    );
  }

  const existingSigners = await listSignersForEnvelopeId(envelopeId, database);
  const existingCopyRecipients = await listCopyRecipientsForEnvelopeId(
    envelopeId,
    database,
  );
  const existingCopyRecipientIds = new Set(
    existingCopyRecipients.map((recipient) => recipient.id),
  );
  const usedCopyRecipientIds = new Set<string>();
  // Left out of the request means "leave them as they are".
  const nextCopyRecipients = (
    parsedInput.copyRecipients ?? existingCopyRecipients
  ).map((recipient, index) => {
    const persistedId =
      recipient.id && existingCopyRecipientIds.has(recipient.id)
        ? recipient.id
        : randomUUID();

    // Two rows of one request claiming to be the same saved recipient.
    if (usedCopyRecipientIds.has(persistedId)) {
      throw new EnvelopeMutationError(
        "Each copy recipient must be unique.",
        400,
      );
    }

    usedCopyRecipientIds.add(persistedId);

    return {
      email: recipient.email,
      id: persistedId,
      name: recipient.name,
      // After every signer, and clear of the numbers the rewrite below
      // parks rows on.
      signOrder: COPY_RECIPIENT_SIGN_ORDER_BASE + index + 1,
    };
  });
  const signerEmails = new Set(
    parsedInput.signers.map((signer) => signer.email.toLowerCase()),
  );

  // Checked by the schema when both lists arrive together. This covers a
  // request that names only signers, one of whom is already a copy recipient.
  if (
    nextCopyRecipients.some((recipient) =>
      signerEmails.has(recipient.email.toLowerCase()),
    )
  ) {
    throw new EnvelopeMutationError(duplicateCopyRecipientEmailMessage, 400);
  }

  const existingSignerIds = new Set(existingSigners.map((signer) => signer.id));
  const usedSignerIds = new Set<string>();
  const updatedAt = Math.floor(Date.now() / 1000);
  const nextSigners = parsedInput.signers.map((signer, index) => {
    const persistedSignerId =
      signer.id && existingSignerIds.has(signer.id) ? signer.id : randomUUID();

    if (usedSignerIds.has(persistedSignerId)) {
      throw new EnvelopeMutationError("Each signer must be unique.", 400);
    }

    usedSignerIds.add(persistedSignerId);

    return {
      // undefined keeps the saved hash; null clears it.
      accessCodeHash:
        signer.accessCode === undefined
          ? undefined
          : signer.accessCode === null
            ? null
            : hashAccessCode(signer.accessCode),
      email: signer.email,
      id: persistedSignerId,
      name: signer.name,
      requireEmailCode: signer.requireEmailCode,
      signatureMeaning: signer.signatureMeaning,
      signOrder: index + 1,
    };
  });

  await withTransaction(async (tx) => {
    await lockDraftEnvelope(userId, envelopeId, tx);

    // Copy recipients hold nothing but a name and an address while the
    // envelope is a draft, so they are simply written again below.
    await tx.query(
      `DELETE FROM signers WHERE envelope_id = $1 AND role = 'cc'`,
      [envelopeId],
    );

    if (existingSigners.length > 0) {
      await tx.query(
        `
          UPDATE signers
          SET
            email = id || '@temp.invalid',
            sign_order = sign_order + 1000,
            updated_at = $1
          WHERE envelope_id = $2
        `,
        [updatedAt, envelopeId],
      );
    }

    for (const signer of nextSigners) {
      if (existingSignerIds.has(signer.id)) {
        await tx.query(
          `
            UPDATE signers
            SET
              name = $1,
              email = $2,
              sign_order = $3,
              updated_at = $4,
              access_code_hash = CASE WHEN $7::boolean THEN $8 ELSE access_code_hash END,
              require_email_code = COALESCE($9, require_email_code),
              signature_meaning = CASE WHEN $10::boolean THEN $11 ELSE signature_meaning END
            WHERE id = $5 AND envelope_id = $6
          `,
          [
            signer.name,
            signer.email,
            signer.signOrder,
            updatedAt,
            signer.id,
            envelopeId,
            signer.accessCodeHash !== undefined,
            signer.accessCodeHash ?? null,
            signer.requireEmailCode ?? null,
            signer.signatureMeaning !== undefined,
            signer.signatureMeaning ?? null,
          ],
        );
      } else {
        await tx.query(
          `
            INSERT INTO signers (
              id,
              envelope_id,
              name,
              email,
              sign_order,
              status,
              signing_token_hash,
              signing_token_expires_at,
              turn_started_at,
              last_notified_at,
              last_nudged_at,
              signed_at,
              declined_at,
              decline_reason,
              created_at,
              updated_at,
              access_code_hash,
              require_email_code,
              signature_meaning
            ) VALUES (
              $1, $2, $3, $4, $5, 'pending', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, $6, $7, $8, $9, $10
            )
          `,
          [
            signer.id,
            envelopeId,
            signer.name,
            signer.email,
            signer.signOrder,
            updatedAt,
            updatedAt,
            signer.accessCodeHash ?? null,
            signer.requireEmailCode ?? false,
            signer.signatureMeaning ?? null,
          ],
        );
      }
    }

    await tx.query(
      `
        DELETE FROM signers
        WHERE envelope_id = $1
          AND id NOT IN (${buildInClausePlaceholders(nextSigners.length, 2)})
      `,
      [envelopeId, ...nextSigners.map((signer) => signer.id)],
    );

    for (const recipient of nextCopyRecipients) {
      await tx.query(
        `
          INSERT INTO signers (
            id, envelope_id, name, email, sign_order, status, role,
            created_at, updated_at
          ) VALUES ($1, $2, $3, $4, $5, 'pending', 'cc', $6, $6)
        `,
        [
          recipient.id,
          envelopeId,
          recipient.name,
          recipient.email,
          recipient.signOrder,
          updatedAt,
        ],
      );
    }

    await tx.query(
      `
        UPDATE envelopes
        SET updated_at = $1
        WHERE id = $2 AND user_id = $3
      `,
      [updatedAt, envelopeId, userId],
    );
  }, database);

  const checks = await listSignerCheckSettings(envelopeId, database);

  return replaceSignersResponseSchema.parse({
    copyRecipients: nextCopyRecipients.map(({ email, id, name }) => ({
      email,
      id,
      name,
    })),
    envelopeId,
    redirectPath: `/envelopes/${envelopeId}/prepare`,
    signers: (await listSignersForEnvelopeId(envelopeId, database)).map(
      (signer) => ({
        email: signer.email,
        hasAccessCode: checks.get(signer.id)?.hasAccessCode ?? false,
        id: signer.id,
        name: signer.name,
        requireEmailCode: checks.get(signer.id)?.requireEmailCode ?? false,
        signatureMeaning: checks.get(signer.id)?.signatureMeaning ?? null,
        signOrder: signer.signOrder,
      }),
    ),
    updatedAt,
  }) as ReplaceDraftSignersResult;
}

export async function deleteDraftEnvelope(
  userId: string,
  envelopeId: string,
  {
    database = getDb(),
    storageService = createStorageService(),
  }: {
    database?: DbExecutor;
    storageService?: StorageService;
  } = {},
): Promise<EnvelopeRecord> {
  const envelope = await getEnvelopeByIdForUser(userId, envelopeId, database);

  if (!envelope) {
    throw new EnvelopeMutationError("Envelope not found.", 404);
  }

  if (envelope.status !== "draft") {
    throw new EnvelopeMutationError(
      "Only draft envelopes can be deleted.",
      409,
    );
  }

  const deleteResult = await database.query(
    `
      DELETE FROM envelopes
      WHERE id = $1 AND user_id = $2 AND status = 'draft'
    `,
    [envelopeId, userId],
  );

  if (deleteResult.rowCount !== 1) {
    throw new EnvelopeMutationError(
      "This draft envelope can no longer be deleted.",
      409,
    );
  }

  await storageService.deleteObject(envelope.sourcePdfKey).catch((error) => {
    console.error(
      `Failed to delete source PDF for draft envelope ${envelopeId}:`,
      error,
    );
  });
  await storageService
    .deleteObject(
      buildEnvelopeThumbnailKey({
        envelopeId,
        sourcePdfKey: envelope.sourcePdfKey,
        userId,
      }),
    )
    .catch((error) => {
      console.error(
        `Failed to delete the thumbnail for draft envelope ${envelopeId}:`,
        error,
      );
    });

  return envelope;
}

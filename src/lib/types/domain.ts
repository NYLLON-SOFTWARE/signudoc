export const MAX_SIGNERS_PER_ENVELOPE = 10;
/** People who get a copy of the finished document without signing. */
export const MAX_COPY_RECIPIENTS_PER_ENVELOPE = 10;
export const MAX_UPLOAD_SIZE_BYTES = 20 * 1024 * 1024;
export const SIGNING_LINK_TTL_SECONDS = 7 * 24 * 60 * 60;
export const RECIPIENT_DOWNLOAD_LINK_TTL_SECONDS = 7 * 24 * 60 * 60;
export const MANUAL_NUDGE_COOLDOWN_SECONDS = 24 * 60 * 60;

/** How long signers get, in days: what the send step offers, and its limits. */
export const ENVELOPE_DEADLINE_DAY_OPTIONS = [3, 7, 14, 30, 60, 90] as const;
export const DEFAULT_ENVELOPE_DEADLINE_DAYS = 30;
export const MAX_ENVELOPE_DEADLINE_DAYS = 365;

/**
 * Automatic reminders: how many days apart the send step offers, the limit,
 * and what a new envelope starts with (null is off).
 */
export const ENVELOPE_REMINDER_DAY_OPTIONS = [1, 2, 3, 7] as const;
export const MAX_ENVELOPE_REMINDER_DAYS = 30;
export const DEFAULT_ENVELOPE_REMINDER_DAYS: number | null = null;

export const envelopeStatuses = [
  "draft",
  "sent",
  "completed",
  "declined",
  "voided",
] as const;

export const signerStatuses = [
  "pending",
  "notified",
  "signed",
  "declined",
] as const;

export const fieldTypes = [
  "signature",
  "initials",
  "date",
  "text",
  "checkbox",
  "number",
  "dropdown",
  "radio",
] as const;

export const fieldInputMethods = ["typed", "drawn", "auto"] as const;

export const auditEventTypes = [
  "created",
  "sent",
  "viewed",
  "consented",
  "verified",
  "verification_failed",
  "signed",
  "declined",
  "reminded_manual",
  "email_sent",
  "completed",
  "voided",
  "deadline_changed",
  "expired",
  "reminded_auto",
  "reauthentication_failed",
  "signer_corrected",
] as const;

/**
 * What a signature means, for Part 11 envelopes (21 CFR 11.50(a)(3)). The
 * sender picks one for each signer, and it is printed beside the signature.
 */
export const signatureMeanings = [
  "approval",
  "review",
  "responsibility",
  "authorship",
] as const;

export const auditActorTypes = ["sender", "signer", "system"] as const;

export const downloadFileTypes = ["signed", "evidence"] as const;

export const emailTemplateKinds = [
  "account_closure_request",
  "contact_form",
  "email_verification",
  "signing_invitation",
  "signing_code",
  "change_email_confirmation",
  "manual_nudge",
  "automatic_reminder",
  "completion_notification",
  "download_links",
  "decline_notification",
  "void_notification",
  "password_reset",
  "retention_notice",
  "expiry_notice",
  "test_email",
  "signing_lock_alert",
] as const;

export type EnvelopeStatus = (typeof envelopeStatuses)[number];
export type SignerStatus = (typeof signerStatuses)[number];
export type FieldType = (typeof fieldTypes)[number];
export type FieldInputMethod = (typeof fieldInputMethods)[number];
export type AuditEventType = (typeof auditEventTypes)[number];
export type AuditActorType = (typeof auditActorTypes)[number];
export type DownloadFileType = (typeof downloadFileTypes)[number];
export type SignatureMeaning = (typeof signatureMeanings)[number];
export type EmailTemplateKind = (typeof emailTemplateKinds)[number];

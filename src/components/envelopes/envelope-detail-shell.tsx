"use client";

import {
  CheckIcon,
  ClockIcon,
  DownloadIcon,
  MinusIcon,
  PencilIcon,
  XIcon,
  type LucideIcon,
} from "lucide-react";
import Link from "next/link";
import { type ReactNode, useState } from "react";

import { DocumentThumbnail } from "@/components/shared/document-thumbnail";
import { ShellButton } from "@/components/shared/form-shell";
import { Textarea } from "@/components/ui/textarea";
import { StatusPanel } from "@/components/shared/status-panel";
import { SaveTemplateDialog } from "@/components/templates/save-template-dialog";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import type {
  EnvelopeDetailData,
  EnvelopeDetailTimelineItem,
} from "@/lib/envelopes";
import { formatReminderInterval } from "@/lib/services/reminders";
import {
  DEFAULT_ENVELOPE_DEADLINE_DAYS,
  ENVELOPE_DEADLINE_DAY_OPTIONS,
  ENVELOPE_REMINDER_DAY_OPTIONS,
} from "@/lib/types/domain";
import { getSignerPalette } from "./signer-palette";

type EnvelopeDetailShellProps = {
  envelopeId: string;
  initialState?: "error" | "not-found";
  record?: EnvelopeDetailData;
};

type EnvelopeStatus = "draft" | "sent" | "completed" | "declined" | "voided";

type SignerStatus = "signed" | "waiting" | "declined" | "pending";

type TimelineTone = "accent" | "danger" | "neutral" | "success";
type DownloadFileType = "evidence" | "signed";

type EnvelopeDetailSigner = {
  color?: string;
  email: string;
  id: string;
  metaLabel: string;
  name: string;
  order: number;
  status: SignerStatus;
  statusDateLabel?: string;
  tint?: string;
};

type EnvelopeDetailRecord = {
  createdAtLabel: string;
  signers: readonly EnvelopeDetailSigner[];
  status: EnvelopeStatus;
  timeline: readonly EnvelopeDetailTimelineItem[];
  title: string;
};

type ModalState =
  | "change-deadline"
  | "change-reminders"
  | "correct-signer"
  | "delete-draft"
  | "save-template"
  | "void-envelope"
  | null;

const statusPillClasses: Record<EnvelopeStatus, string> = {
  completed: "pill-success",
  declined: "pill-danger",
  draft: "pill-neutral",
  sent: "pill-accent",
  voided: "pill-neutral",
};

const statusLabelMap: Record<EnvelopeStatus, string> = {
  completed: "Completed",
  declined: "Declined",
  draft: "Draft",
  sent: "Sent",
  voided: "Voided",
};

const signerStatusPillClasses: Record<SignerStatus, string> = {
  declined: "pill-danger",
  pending: "pill-neutral",
  signed: "pill-success",
  waiting: "pill-accent",
};

const signerStatusLabelMap: Record<SignerStatus, string> = {
  declined: "Declined",
  pending: "Pending",
  signed: "Signed",
  waiting: "Waiting",
};

const signerStatusIcons: Record<SignerStatus, LucideIcon> = {
  declined: XIcon,
  pending: MinusIcon,
  signed: CheckIcon,
  waiting: ClockIcon,
};

const timelineToneClasses: Record<TimelineTone, string> = {
  accent: "bg-(--accent)",
  danger: "bg-(--danger)",
  neutral: "bg-(--border-strong)",
  success: "bg-(--success)",
};

export function EnvelopeDetailShell({
  envelopeId,
  initialState,
  record,
}: EnvelopeDetailShellProps) {
  const [activeModal, setActiveModal] = useState<ModalState>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [isChangingDeadline, setIsChangingDeadline] = useState(false);
  const [isChangingReminders, setIsChangingReminders] = useState(false);
  const [isCorrectingSigner, setIsCorrectingSigner] = useState(false);
  const [isDeletingDraft, setIsDeletingDraft] = useState(false);
  const [isSendingReminder, setIsSendingReminder] = useState(false);
  const [isVoidingEnvelope, setIsVoidingEnvelope] = useState(false);
  const [correctingSigner, setCorrectingSigner] =
    useState<EnvelopeDetailSigner | null>(null);
  const [voidReason, setVoidReason] = useState("");
  const [savedTemplateName, setSavedTemplateName] = useState<string | null>(
    null,
  );

  function handleRetry() {
    window.location.reload();
  }

  if (initialState === "error") {
    return (
      <StatusPanel
        description="Couldn't load this envelope. Please try again."
        footer={
          <ShellButton onClick={handleRetry} variant="secondary">
            Retry
          </ShellButton>
        }
        title="Couldn't load this envelope"
        tone="error"
      />
    );
  }

  if (initialState === "not-found") {
    return (
      <StatusPanel
        action={{ href: "/dashboard", label: "Back to documents" }}
        description="We couldn't find this envelope, or you no longer have access to it."
        eyebrow="Unavailable"
        title="This envelope is unavailable"
        tone="error"
      />
    );
  }

  if (!record) {
    return (
      <StatusPanel
        description="Couldn't load this envelope. Please try again."
        footer={
          <ShellButton onClick={handleRetry} variant="secondary">
            Retry
          </ShellButton>
        }
        title="Couldn't load this envelope"
        tone="error"
      />
    );
  }

  const activeRecord: EnvelopeDetailRecord = {
    createdAtLabel: record.createdAtLabel,
    signers: record.signers,
    status: record.status,
    timeline: record.timeline,
    title: record.title,
  };
  const deadline = activeRecord.status === "sent" ? record.deadline : null;
  const isExpired = Boolean(deadline?.expired);
  const manualReminderState = record.manualReminder ?? null;
  const reminderLimited =
    activeRecord.status === "sent" &&
    manualReminderState !== null &&
    !manualReminderState.canSend;
  const reminderHelperText =
    activeRecord.status === "sent" && manualReminderState?.nextAvailableAtLabel
      ? `You can send another reminder after ${manualReminderState.nextAvailableAtLabel}.`
      : null;
  const deadlineText = !deadline
    ? null
    : isExpired
      ? `Expired ${deadline.expiresAtLabel}. Nobody can sign until you set a new deadline.`
      : deadline.expiresAtLabel
        ? `Expires ${deadline.expiresAtLabel}.`
        : "No deadline. Each signing link lasts seven days.";
  const reminderIntervalDays = record.reminderIntervalDays ?? null;
  const remindersText =
    reminderIntervalDays === null
      ? "Automatic reminders are off."
      : `Automatic reminders: ${formatReminderInterval(reminderIntervalDays).toLowerCase()}.`;
  const activeSigner =
    activeRecord.status === "sent"
      ? activeRecord.signers.find((signer) => signer.status === "waiting")
      : null;

  function handleDownload(fileType: DownloadFileType) {
    // This starts a file download from an API route, not a page navigation.
    // eslint-disable-next-line @next/next/no-location-assign-relative-destination
    window.location.assign(
      `/api/envelopes/${encodeURIComponent(envelopeId)}/download?type=${fileType}`,
    );
  }

  async function handleSendReminder() {
    if (!activeSigner) {
      return;
    }

    setActionError(null);
    setIsSendingReminder(true);

    try {
      const response = await fetch(`/api/envelopes/${envelopeId}/nudge`, {
        method: "POST",
      });
      const payload = (await response.json().catch(() => null)) as {
        error?: string;
      } | null;

      if (
        response.ok ||
        response.status === 404 ||
        response.status === 409 ||
        response.status === 429
      ) {
        window.location.reload();
        return;
      }

      setActionError(payload?.error ?? "Unable to send a reminder right now.");
    } finally {
      setIsSendingReminder(false);
    }
  }

  async function handleConfirmChangeDeadline(expiresInDays: number) {
    setActionError(null);
    setIsChangingDeadline(true);

    try {
      const response = await fetch(`/api/envelopes/${envelopeId}/deadline`, {
        body: JSON.stringify({ expiresInDays }),
        headers: { "content-type": "application/json" },
        method: "POST",
      });
      const payload = (await response.json().catch(() => null)) as {
        error?: string;
      } | null;

      if (response.ok || response.status === 404 || response.status === 409) {
        window.location.reload();
        return;
      }

      setActionError(payload?.error ?? "Unable to change the deadline.");
    } catch {
      setActionError("Unable to change the deadline.");
    } finally {
      setIsChangingDeadline(false);
    }
  }

  async function handleConfirmCorrectSigner(next: {
    email: string;
    name: string;
  }) {
    if (!correctingSigner) {
      return;
    }

    setActionError(null);
    setIsCorrectingSigner(true);

    try {
      const response = await fetch(
        `/api/envelopes/${encodeURIComponent(envelopeId)}/signers/${encodeURIComponent(correctingSigner.id)}`,
        {
          body: JSON.stringify(next),
          headers: { "content-type": "application/json" },
          method: "PATCH",
        },
      );
      const payload = (await response.json().catch(() => null)) as {
        error?: string;
      } | null;

      if (response.ok) {
        window.location.reload();
        return;
      }

      setActionError(payload?.error ?? "Unable to correct this signer.");
    } catch {
      setActionError("Unable to correct this signer.");
    } finally {
      setIsCorrectingSigner(false);
    }
  }

  async function handleConfirmChangeReminders(intervalDays: number | null) {
    setActionError(null);
    setIsChangingReminders(true);

    try {
      const response = await fetch(`/api/envelopes/${envelopeId}/reminders`, {
        body: JSON.stringify({ reminderIntervalDays: intervalDays }),
        headers: { "content-type": "application/json" },
        method: "POST",
      });
      const payload = (await response.json().catch(() => null)) as {
        error?: string;
      } | null;

      if (response.ok || response.status === 404 || response.status === 409) {
        window.location.reload();
        return;
      }

      setActionError(payload?.error ?? "Unable to change the reminders.");
    } catch {
      setActionError("Unable to change the reminders.");
    } finally {
      setIsChangingReminders(false);
    }
  }

  async function handleConfirmDeleteDraft() {
    setActionError(null);
    setIsDeletingDraft(true);

    try {
      const response = await fetch(`/api/envelopes/${envelopeId}`, {
        method: "DELETE",
      });
      const payload = (await response.json().catch(() => null)) as {
        error?: string;
        redirectPath?: string;
      } | null;

      if (!response.ok) {
        setActionError(payload?.error ?? "Unable to delete this draft.");
        return;
      }

      window.location.assign(payload?.redirectPath ?? "/dashboard");
    } finally {
      setIsDeletingDraft(false);
    }
  }

  async function handleConfirmVoidEnvelope() {
    setActionError(null);
    setIsVoidingEnvelope(true);

    try {
      const response = await fetch(`/api/envelopes/${envelopeId}/void`, {
        body: JSON.stringify({ reason: voidReason }),
        headers: { "content-type": "application/json" },
        method: "POST",
      });
      const payload = (await response.json().catch(() => null)) as {
        error?: string;
        redirectPath?: string;
      } | null;

      if (response.ok) {
        window.location.assign(
          payload?.redirectPath ??
            `/envelopes/${encodeURIComponent(envelopeId)}`,
        );
        return;
      }

      if (response.status === 404 || response.status === 409) {
        window.location.reload();
        return;
      }

      setActionError(payload?.error ?? "Unable to void this envelope.");
    } finally {
      setIsVoidingEnvelope(false);
    }
  }

  return (
    <div className="space-y-5">
      <section className="panel p-5 sm:p-8" data-animate="enter">
        <Link
          className="inline-flex items-center text-sm font-semibold text-(--secondary) transition hover:text-(--accent-ink)"
          href="/dashboard"
        >
          ← Documents
        </Link>

        <div className="mt-5 flex flex-col gap-6 lg:flex-row lg:items-center lg:justify-between">
          <div className="flex min-w-0 items-center gap-5">
            <span className="hidden h-28 shrink-0 items-center justify-center rounded-2xl bg-(--surface) px-4 py-3 sm:flex">
              <DocumentThumbnail
                envelopeId={envelopeId}
                title={activeRecord.title}
              />
            </span>
            <div className="min-w-0 space-y-2.5">
              <h1
                className={`text-[clamp(1.5rem,3vw,1.875rem)] font-extrabold leading-tight tracking-[-0.03em] ${
                  activeRecord.status === "voided"
                    ? "text-(--tertiary)"
                    : "text-(--fg)"
                }`}
              >
                {activeRecord.title}
              </h1>
              <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
                <span
                  className={`pill ${
                    isExpired
                      ? "pill-danger"
                      : statusPillClasses[activeRecord.status]
                  }`}
                >
                  {isExpired ? "Expired" : statusLabelMap[activeRecord.status]}
                </span>
                <p className="text-sm text-(--secondary)">
                  Created {activeRecord.createdAtLabel}
                </p>
                {record.signatureTypeLabel ? (
                  <span className="pill pill-neutral">
                    {record.signatureTypeLabel}
                  </span>
                ) : null}
              </div>
            </div>
          </div>

          <div className="flex shrink-0 flex-col gap-3 sm:flex-row sm:flex-wrap lg:justify-end">
            {activeRecord.status === "draft" ? (
              <>
                <ShellButton
                  onClick={() => setActiveModal("delete-draft")}
                  variant="secondary"
                >
                  Delete draft
                </ShellButton>
                <ShellButton href={`/envelopes/${envelopeId}/prepare`}>
                  Continue editing
                </ShellButton>
              </>
            ) : null}

            {activeRecord.status === "sent" ? (
              <>
                <ShellButton
                  onClick={() => setActiveModal("void-envelope")}
                  variant="secondary"
                >
                  Void envelope
                </ShellButton>
                <ShellButton
                  disabled={!activeSigner || reminderLimited}
                  loading={isSendingReminder}
                  onClick={handleSendReminder}
                >
                  Send reminder
                </ShellButton>
              </>
            ) : null}

            {activeRecord.status === "completed" ? (
              <>
                <ShellButton
                  onClick={() => handleDownload("evidence")}
                  variant="secondary"
                >
                  Download certificate
                </ShellButton>
                <ShellButton onClick={() => handleDownload("signed")}>
                  <DownloadIcon
                    aria-hidden="true"
                    className="size-[1.125rem]"
                    strokeWidth={2.2}
                  />
                  Download signed PDF
                </ShellButton>
              </>
            ) : null}

            {activeRecord.status === "declined" ||
            activeRecord.status === "voided" ? (
              <ShellButton
                onClick={() => handleDownload("evidence")}
                variant="secondary"
              >
                Download certificate
              </ShellButton>
            ) : null}

            {activeRecord.status !== "draft" ? (
              <ShellButton
                onClick={() =>
                  // A file download from an API route, not a page navigation.
                  // eslint-disable-next-line @next/next/no-location-assign-relative-destination
                  window.location.assign(
                    `/api/envelopes/${encodeURIComponent(envelopeId)}/audit`,
                  )
                }
                variant="secondary"
              >
                Export audit trail
              </ShellButton>
            ) : null}
          </div>
        </div>

        {reminderHelperText ? (
          <p className="mt-4 text-sm leading-6 text-(--secondary) lg:text-right">
            {reminderHelperText}
          </p>
        ) : null}

        {deadlineText ? (
          <div
            className={`mt-5 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between ${
              isExpired ? "notice notice-danger" : "well px-5 py-3.5"
            }`}
          >
            <p
              className={
                isExpired ? undefined : "text-sm leading-6 text-(--secondary)"
              }
            >
              {deadlineText}
            </p>
            <button
              className="btn-quiet shrink-0"
              onClick={() => {
                setActionError(null);
                setActiveModal("change-deadline");
              }}
              type="button"
            >
              {isExpired ? "Set a new deadline" : "Change deadline"}
            </button>
          </div>
        ) : null}

        {deadline ? (
          <div className="well mt-3 flex flex-col gap-3 px-5 py-3.5 sm:flex-row sm:items-center sm:justify-between">
            <p className="text-sm leading-6 text-(--secondary)">
              {remindersText}
            </p>
            <button
              className="btn-quiet shrink-0"
              onClick={() => {
                setActionError(null);
                setActiveModal("change-reminders");
              }}
              type="button"
            >
              Change reminders
            </button>
          </div>
        ) : null}

        {savedTemplateName ? (
          <div
            className={`notice notice-success flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between ${
              deadlineText || deadline ? "mt-3" : "mt-5"
            }`}
            role="status"
          >
            <p>Saved as the template &ldquo;{savedTemplateName}&rdquo;.</p>
            <Link
              className="shrink-0 underline underline-offset-4"
              href="/templates"
            >
              View templates
            </Link>
          </div>
        ) : activeRecord.signers.length > 0 ? (
          <div
            className={`well flex flex-col gap-3 px-5 py-3.5 sm:flex-row sm:items-center sm:justify-between ${
              deadlineText || deadline ? "mt-3" : "mt-5"
            }`}
          >
            <p className="text-sm leading-6 text-(--secondary)">
              Send this kind of document often? Keep its fields and signing
              order as a template.
            </p>
            <button
              className="btn-quiet shrink-0"
              onClick={() => {
                setActionError(null);
                setActiveModal("save-template");
              }}
              type="button"
            >
              Save as template
            </button>
          </div>
        ) : null}

        {actionError ? (
          <div className="notice notice-danger mt-5" role="alert">
            {actionError}
          </div>
        ) : null}
      </section>

      <section
        className="grid gap-5 lg:grid-cols-[minmax(0,1.08fr)_minmax(0,0.92fr)]"
        data-animate="enter"
        data-animate-delay="1"
      >
        <article className="panel p-5 sm:p-7">
          <div className="flex items-center justify-between gap-3">
            <h2 className="text-lg font-extrabold text-(--fg)">Signers</h2>
            <span className="pill pill-neutral">
              {activeRecord.signers.length} total
            </span>
          </div>

          <ol className="mt-4 space-y-3">
            {activeRecord.signers.map((signer, index) => {
              const palette =
                signer.color && signer.tint
                  ? { color: signer.color, tint: signer.tint }
                  : getSignerPalette(index);
              const StatusIcon = signerStatusIcons[signer.status];

              return (
                <li className="well p-4" key={signer.id}>
                  <div className="flex items-start gap-3.5">
                    <span
                      aria-hidden="true"
                      className="inline-flex size-10 shrink-0 items-center justify-center rounded-full text-sm font-bold"
                      style={{
                        backgroundColor: palette.tint,
                        color: palette.color,
                      }}
                    >
                      {signer.order}
                    </span>

                    <div className="min-w-0 flex-1">
                      <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
                        <div className="min-w-0">
                          <p className="truncate text-[0.9375rem] font-bold text-(--fg)">
                            {signer.name}
                          </p>
                          <p className="truncate text-sm text-(--secondary)">
                            {signer.email}
                          </p>
                        </div>

                        <div className="flex items-center gap-2 sm:flex-col sm:items-end sm:gap-1.5">
                          <span
                            className={`pill ${signerStatusPillClasses[signer.status]}`}
                          >
                            <StatusIcon
                              aria-hidden="true"
                              className="size-3.5"
                              strokeWidth={2.6}
                            />
                            {signerStatusLabelMap[signer.status]}
                          </span>
                          {signer.statusDateLabel ? (
                            <p className="text-xs text-(--tertiary)">
                              {signer.statusDateLabel}
                            </p>
                          ) : null}
                          {activeRecord.status === "sent" &&
                          !record.part11 &&
                          (signer.status === "waiting" ||
                            signer.status === "pending") ? (
                            <button
                              className="btn-quiet inline-flex items-center gap-1.5"
                              onClick={() => {
                                setActionError(null);
                                setCorrectingSigner(signer);
                                setActiveModal("correct-signer");
                              }}
                              type="button"
                            >
                              <PencilIcon
                                aria-hidden="true"
                                className="size-3.5"
                                strokeWidth={2.4}
                              />
                              Change
                            </button>
                          ) : null}
                        </div>
                      </div>

                      <p className="mt-2 text-sm leading-6 text-(--secondary)">
                        {signer.metaLabel}
                      </p>
                    </div>
                  </div>
                </li>
              );
            })}
          </ol>

          {record.copyRecipients && record.copyRecipients.length > 0 ? (
            <div className="mt-6">
              <h3 className="text-[0.9375rem] font-extrabold text-(--fg)">
                Receives a copy
              </h3>
              <p className="mt-1 text-sm leading-6 text-(--secondary)">
                {activeRecord.status === "completed"
                  ? "Sent the finished document and its certificate."
                  : "Gets the finished document once everyone has signed."}
              </p>
              <ul className="mt-3 space-y-2">
                {record.copyRecipients.map((recipient) => (
                  <li className="well px-4 py-3" key={recipient.id}>
                    <p className="truncate text-[0.9375rem] font-bold text-(--fg)">
                      {recipient.name}
                    </p>
                    <p className="truncate text-sm text-(--secondary)">
                      {recipient.email}
                    </p>
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
        </article>

        <article className="panel p-5 sm:p-7">
          <div className="flex items-center justify-between gap-3">
            <h2 className="text-lg font-extrabold text-(--fg)">Timeline</h2>
            <span className="pill pill-neutral">
              {activeRecord.timeline.length} events
            </span>
          </div>

          <ol className="mt-5 space-y-5">
            {activeRecord.timeline.map((event, index) => (
              <li className="relative pl-7" key={event.id}>
                <span
                  aria-hidden="true"
                  className={`absolute left-0 top-1.5 size-3 rounded-full ring-4 ring-white ${timelineToneClasses[event.tone]}`}
                />
                {index < activeRecord.timeline.length - 1 ? (
                  <span
                    aria-hidden="true"
                    className="absolute left-[5.5px] top-5 h-[calc(100%+0.5rem)] w-px bg-(--border)"
                  />
                ) : null}
                <p className="text-[0.8125rem] font-semibold text-(--tertiary)">
                  {event.timestamp}
                </p>
                <p className="mt-0.5 text-sm leading-6 text-(--fg)">
                  {event.description}
                </p>
              </li>
            ))}
          </ol>
        </article>
      </section>

      {activeModal === "change-deadline" ? (
        <DeadlineDialog
          errorMessage={actionError}
          expired={isExpired}
          onCancel={() => setActiveModal(null)}
          onConfirm={handleConfirmChangeDeadline}
          processing={isChangingDeadline}
        />
      ) : null}

      {activeModal === "change-reminders" ? (
        <RemindersDialog
          errorMessage={actionError}
          initialIntervalDays={reminderIntervalDays}
          onCancel={() => setActiveModal(null)}
          onConfirm={handleConfirmChangeReminders}
          processing={isChangingReminders}
        />
      ) : null}

      {activeModal === "correct-signer" && correctingSigner ? (
        <CorrectSignerDialog
          email={correctingSigner.email}
          errorMessage={actionError}
          name={correctingSigner.name}
          onCancel={() => {
            setActiveModal(null);
            setCorrectingSigner(null);
          }}
          onConfirm={handleConfirmCorrectSigner}
          processing={isCorrectingSigner}
        />
      ) : null}

      {activeModal === "save-template" ? (
        <SaveTemplateDialog
          envelopeId={envelopeId}
          initialName={activeRecord.title}
          onCancel={() => setActiveModal(null)}
          onSaved={(templateName) => {
            setActiveModal(null);
            setSavedTemplateName(templateName);
          }}
          signers={[...activeRecord.signers]
            .sort((left, right) => left.order - right.order)
            .map((signer) => ({ id: signer.id, name: signer.name }))}
        />
      ) : null}

      {activeModal === "delete-draft" ? (
        <ConfirmationDialog
          confirmLabel="Delete draft"
          description={[
            "This draft has not been sent yet.",
            "Deleting it will permanently remove the draft and its placed fields.",
          ]}
          errorMessage={actionError}
          onCancel={() => setActiveModal(null)}
          onConfirm={handleConfirmDeleteDraft}
          processing={isDeletingDraft}
          title="Delete this draft?"
        />
      ) : null}

      {activeModal === "void-envelope" ? (
        <ConfirmationDialog
          confirmLabel="Void envelope"
          description={[
            "This will cancel the signing process.",
            "Notified signers will be informed that the envelope has been voided.",
            "This action cannot be undone.",
          ]}
          confirmDisabled={record.part11 && voidReason.trim().length === 0}
          errorMessage={actionError}
          onCancel={() => setActiveModal(null)}
          onConfirm={handleConfirmVoidEnvelope}
          processing={isVoidingEnvelope}
          title="Void this envelope?"
        >
          <label className="grid gap-2 text-sm">
            <span className="text-[0.8125rem] font-semibold text-(--secondary)">
              {record.part11 ? "Reason (required)" : "Reason (optional)"}
            </span>
            <Textarea
              disabled={isVoidingEnvelope}
              maxLength={1000}
              onChange={(event) => setVoidReason(event.target.value)}
              rows={3}
              value={voidReason}
            />
            <span className="text-xs leading-5 text-(--tertiary)">
              Kept in the envelope&apos;s audit trail.
            </span>
          </label>
        </ConfirmationDialog>
      ) : null}
    </div>
  );
}

type DeadlineDialogProps = {
  errorMessage?: string | null;
  expired: boolean;
  onCancel: () => void;
  onConfirm: (expiresInDays: number) => void | Promise<void>;
  processing?: boolean;
};

function DeadlineDialog({
  errorMessage,
  expired,
  onCancel,
  onConfirm,
  processing = false,
}: DeadlineDialogProps) {
  const [days, setDays] = useState<number>(DEFAULT_ENVELOPE_DEADLINE_DAYS);

  return (
    <Dialog
      open
      onOpenChange={(open) => {
        if (!open && !processing) {
          onCancel();
        }
      }}
    >
      <DialogContent className="max-w-md sm:p-8" showCloseButton={false}>
        <div className="space-y-4">
          <DialogHeader className="space-y-3">
            <DialogTitle>
              {expired ? "Set a new deadline" : "Change the deadline"}
            </DialogTitle>
            <DialogDescription asChild>
              <div className="space-y-2 text-sm leading-6 text-(--secondary)">
                <p>
                  The new deadline counts from now.{" "}
                  {expired
                    ? "The signing link that was already sent will work again."
                    : "The signing link that was already sent keeps working until then."}
                </p>
              </div>
            </DialogDescription>
          </DialogHeader>

          <label className="grid gap-1.5">
            <span className="text-[0.8125rem] font-semibold text-(--secondary)">
              Signing deadline
            </span>
            <select
              autoFocus
              className="field-input"
              disabled={processing}
              onChange={(event) => setDays(Number(event.target.value))}
              value={days}
            >
              {ENVELOPE_DEADLINE_DAY_OPTIONS.map((option) => (
                <option key={option} value={option}>
                  {option} days from now
                </option>
              ))}
            </select>
          </label>

          {errorMessage ? (
            <div className="notice notice-danger" role="alert">
              <p>{errorMessage}</p>
            </div>
          ) : null}

          <div className="flex flex-col-reverse gap-3 pt-2 sm:flex-row sm:justify-end">
            <ShellButton
              disabled={processing}
              onClick={onCancel}
              variant="secondary"
            >
              Cancel
            </ShellButton>
            <ShellButton loading={processing} onClick={() => onConfirm(days)}>
              {processing ? "Saving..." : "Save deadline"}
            </ShellButton>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

type RemindersDialogProps = {
  errorMessage?: string | null;
  initialIntervalDays: number | null;
  onCancel: () => void;
  onConfirm: (intervalDays: number | null) => void | Promise<void>;
  processing?: boolean;
};

function RemindersDialog({
  errorMessage,
  initialIntervalDays,
  onCancel,
  onConfirm,
  processing = false,
}: RemindersDialogProps) {
  const [intervalDays, setIntervalDays] = useState<number | null>(
    initialIntervalDays,
  );
  // An interval set some other way than these choices is still offered.
  const options = [
    ...new Set([
      ...ENVELOPE_REMINDER_DAY_OPTIONS,
      ...(initialIntervalDays === null ? [] : [initialIntervalDays]),
    ]),
  ].sort((left, right) => left - right);

  return (
    <Dialog
      open
      onOpenChange={(open) => {
        if (!open && !processing) {
          onCancel();
        }
      }}
    >
      <DialogContent className="max-w-md sm:p-8" showCloseButton={false}>
        <div className="space-y-4">
          <DialogHeader className="space-y-3">
            <DialogTitle>Automatic reminders</DialogTitle>
            <DialogDescription asChild>
              <div className="space-y-2 text-sm leading-6 text-(--secondary)">
                <p>
                  A reminder goes to the signer whose turn it is when they have
                  not heard from you for this long. Reminders stop once everyone
                  has signed or the deadline passes.
                </p>
              </div>
            </DialogDescription>
          </DialogHeader>

          <label className="grid gap-1.5">
            <span className="text-[0.8125rem] font-semibold text-(--secondary)">
              Send a reminder
            </span>
            <select
              autoFocus
              className="field-input"
              disabled={processing}
              onChange={(event) =>
                setIntervalDays(
                  event.target.value === "off"
                    ? null
                    : Number(event.target.value),
                )
              }
              value={intervalDays ?? "off"}
            >
              <option value="off">{formatReminderInterval(null)}</option>
              {options.map((option) => (
                <option key={option} value={option}>
                  {formatReminderInterval(option)}
                </option>
              ))}
            </select>
          </label>

          {errorMessage ? (
            <div className="notice notice-danger" role="alert">
              <p>{errorMessage}</p>
            </div>
          ) : null}

          <div className="flex flex-col-reverse gap-3 pt-2 sm:flex-row sm:justify-end">
            <ShellButton
              disabled={processing}
              onClick={onCancel}
              variant="secondary"
            >
              Cancel
            </ShellButton>
            <ShellButton
              loading={processing}
              onClick={() => onConfirm(intervalDays)}
            >
              {processing ? "Saving..." : "Save reminders"}
            </ShellButton>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

type CorrectSignerDialogProps = {
  email: string;
  errorMessage?: string | null;
  name: string;
  onCancel: () => void;
  onConfirm: (next: { email: string; name: string }) => void | Promise<void>;
  processing?: boolean;
};

function CorrectSignerDialog({
  email,
  errorMessage,
  name,
  onCancel,
  onConfirm,
  processing = false,
}: CorrectSignerDialogProps) {
  const [nextName, setNextName] = useState(name);
  const [nextEmail, setNextEmail] = useState(email);

  return (
    <Dialog
      open
      onOpenChange={(open) => {
        if (!open && !processing) {
          onCancel();
        }
      }}
    >
      <DialogContent className="max-w-md sm:p-8" showCloseButton={false}>
        <div className="space-y-4">
          <DialogHeader className="space-y-3">
            <DialogTitle>Correct this signer</DialogTitle>
            <DialogDescription asChild>
              <div className="space-y-2 text-sm leading-6 text-(--secondary)">
                <p>
                  The signing link already sent to this person will stop
                  working. If it is their turn, a new invitation goes to the
                  corrected address.
                </p>
              </div>
            </DialogDescription>
          </DialogHeader>

          <label className="grid gap-1.5">
            <span className="text-[0.8125rem] font-semibold text-(--secondary)">
              Name
            </span>
            <input
              autoFocus
              className="field-input"
              disabled={processing}
              onChange={(event) => setNextName(event.target.value)}
              value={nextName}
            />
          </label>

          <label className="grid gap-1.5">
            <span className="text-[0.8125rem] font-semibold text-(--secondary)">
              Email
            </span>
            <input
              className="field-input"
              disabled={processing}
              onChange={(event) => setNextEmail(event.target.value)}
              type="email"
              value={nextEmail}
            />
          </label>

          {errorMessage ? (
            <div className="notice notice-danger" role="alert">
              <p>{errorMessage}</p>
            </div>
          ) : null}

          <div className="flex flex-col-reverse gap-3 pt-2 sm:flex-row sm:justify-end">
            <ShellButton
              disabled={processing}
              onClick={onCancel}
              variant="secondary"
            >
              Cancel
            </ShellButton>
            <ShellButton
              loading={processing}
              onClick={() => onConfirm({ email: nextEmail, name: nextName })}
            >
              {processing ? "Saving..." : "Save"}
            </ShellButton>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

type ConfirmationDialogProps = {
  children?: ReactNode;
  confirmDisabled?: boolean;
  confirmLabel: string;
  description: readonly string[];
  errorMessage?: string | null;
  onCancel: () => void;
  onConfirm: () => void | Promise<void>;
  processing?: boolean;
  title: string;
};

function ConfirmationDialog({
  children,
  confirmDisabled = false,
  confirmLabel,
  description,
  errorMessage,
  onCancel,
  onConfirm,
  processing = false,
  title,
}: ConfirmationDialogProps) {
  return (
    <Dialog
      open
      onOpenChange={(open) => {
        if (!open && !processing) {
          onCancel();
        }
      }}
    >
      <DialogContent className="max-w-md sm:p-8" showCloseButton={false}>
        <div className="space-y-4">
          <DialogHeader className="space-y-3">
            <DialogTitle>{title}</DialogTitle>
            <DialogDescription asChild>
              <div className="space-y-2 text-sm leading-6 text-(--secondary)">
                {description.map((line) => (
                  <p key={line}>{line}</p>
                ))}
              </div>
            </DialogDescription>
          </DialogHeader>

          {children}

          {errorMessage ? (
            <div className="notice notice-danger" role="alert">
              <p>{errorMessage}</p>
            </div>
          ) : null}

          <div className="flex flex-col-reverse gap-3 pt-2 sm:flex-row sm:justify-end">
            <ShellButton
              disabled={processing}
              onClick={onCancel}
              variant="secondary"
            >
              Cancel
            </ShellButton>
            <ShellButton
              disabled={confirmDisabled}
              loading={processing}
              onClick={onConfirm}
              variant="danger"
            >
              {processing ? `${confirmLabel}...` : confirmLabel}
            </ShellButton>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

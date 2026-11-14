import {
  type DbExecutor,
  getDb,
  queryMany,
  queryOne,
} from "./db/connection.ts";
import {
  describeSignerCorrectedEvent,
  verifyAuditChain,
} from "./services/audit.ts";
import {
  listSystemAuditEventsBetween,
  verifySystemAuditChain,
} from "./services/system-audit.ts";
import { sanitizeFileNameSegment } from "./downloads.ts";

// Audit trails as CSV, for an inspector or a records review (21 CFR
// 11.10(b): accurate and complete copies in a form people can read and a
// program can process). Each file starts with the result of checking the
// hash chain, so a copy shows whether the trail was intact when exported.

/**
 * One CSV line. A cell that a spreadsheet would run as a formula is
 * prefixed with an apostrophe, so an exported value can never execute.
 */
function csvRow(cells: readonly unknown[]): string {
  return cells
    .map((cell) => {
      let text =
        cell === null || cell === undefined
          ? ""
          : typeof cell === "object"
            ? JSON.stringify(cell)
            : String(cell);

      if (/^[=+\-@\t\r]/.test(text)) {
        text = `'${text}`;
      }

      return /[",\r\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
    })
    .join(",");
}

export function toCsv(rows: readonly (readonly unknown[])[]): string {
  return `${rows.map(csvRow).join("\r\n")}\r\n`;
}

function isoTime(timestamp: number | null | undefined): string {
  return typeof timestamp === "number"
    ? new Date(timestamp * 1000).toISOString()
    : "";
}

export type AuditCsvExport = { body: string; fileName: string };

export class AuditExportError extends Error {
  readonly statusCode: number;

  constructor(message: string, statusCode: number) {
    super(message);
    this.name = "AuditExportError";
    this.statusCode = statusCode;
  }
}

/** The audit trail of one envelope its sender owns. */
export async function exportEnvelopeAuditCsv(
  userId: string,
  envelopeId: string,
  database: DbExecutor = getDb(),
): Promise<AuditCsvExport> {
  const envelope = await queryOne<{ part11: boolean; title: string }>(
    database,
    `SELECT title, part11 FROM envelopes WHERE id = $1 AND user_id = $2`,
    [envelopeId, userId],
  );

  if (!envelope) {
    throw new AuditExportError("Envelope not found.", 404);
  }

  const rows = await queryMany<{
    actorEmail: string | null;
    actorType: string;
    createdAt: number;
    event: string;
    id: string;
    ipAddress: string | null;
    metadata: Record<string, unknown> | null;
    prevHash: string | null;
    rowHash: string | null;
    sequence: number | null;
    userAgent: string | null;
  }>(
    database,
    `
      SELECT
        id,
        sequence,
        event,
        actor_type AS "actorType",
        actor_email AS "actorEmail",
        ip_address AS "ipAddress",
        user_agent AS "userAgent",
        metadata,
        created_at AS "createdAt",
        prev_hash AS "prevHash",
        row_hash AS "rowHash"
      FROM audit_events
      WHERE envelope_id = $1
      ORDER BY sequence ASC NULLS FIRST, created_at ASC, id ASC
    `,
    [envelopeId],
  );
  const chain = await verifyAuditChain(envelopeId, database);
  const body = toCsv([
    ["Envelope", envelopeId, envelope.title],
    ["Part 11 envelope", envelope.part11 ? "yes" : "no"],
    ["Exported at (UTC)", new Date().toISOString()],
    [
      "Hash chain check",
      chain.ok
        ? `intact (${chain.chainedEvents} chained events)`
        : `BROKEN at sequence ${chain.brokenAtSequence}`,
    ],
    [],
    [
      "sequence",
      "time_utc",
      "event",
      "actor_type",
      "actor_email",
      "ip_address",
      "user_agent",
      "details",
      "event_id",
      "previous_hash",
      "row_hash",
    ],
    ...rows.map((row) => [
      row.sequence,
      isoTime(row.createdAt),
      row.event === "signer_corrected" ? "Signer corrected" : row.event,
      row.actorType,
      row.actorEmail,
      row.ipAddress,
      row.userAgent,
      row.event === "signer_corrected"
        ? describeSignerCorrectedEvent(row.metadata)
        : row.metadata,
      row.id,
      row.prevHash,
      row.rowHash,
    ]),
  ]);

  return {
    body,
    fileName: `${sanitizeFileNameSegment(envelope.title) || "envelope"}-audit-trail.csv`,
  };
}

/** The install's own audit trail between two times, for an administrator. */
export async function exportSystemAuditCsv(
  { from, to }: { from: number; to: number },
  database: DbExecutor = getDb(),
): Promise<AuditCsvExport> {
  const events = await listSystemAuditEventsBetween(from, to, database);
  const chain = await verifySystemAuditChain(database);
  const body = toCsv([
    ["Install audit trail"],
    ["From (UTC)", isoTime(from), "To (UTC)", isoTime(to)],
    ["Exported at (UTC)", new Date().toISOString()],
    [
      "Hash chain check (whole trail)",
      chain.ok
        ? `intact (${chain.events} events)`
        : `BROKEN at sequence ${chain.brokenAtSequence}`,
    ],
    [],
    [
      "sequence",
      "time_utc",
      "event",
      "actor_email",
      "actor_user_id",
      "target_user_id",
      "ip_address",
      "user_agent",
      "details",
      "event_id",
    ],
    ...events.map((event) => [
      event.sequence,
      isoTime(event.createdAt),
      event.event,
      event.actorEmail,
      event.actorUserId,
      event.targetUserId,
      event.ipAddress,
      event.userAgent,
      event.metadata,
      event.id,
    ]),
  ]);

  return { body, fileName: "install-audit-trail.csv" };
}

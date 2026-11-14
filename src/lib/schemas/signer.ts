import { z } from "zod";

import {
  MAX_COPY_RECIPIENTS_PER_ENVELOPE,
  MAX_SIGNERS_PER_ENVELOPE,
  signatureMeanings,
  signerStatuses,
} from "../types/domain.ts";
import {
  emailSchema,
  idSchema,
  nameSchema,
  optionalTrimmedString,
  unixTimestampSchema,
} from "./common.ts";

export const signerStatusSchema = z.enum(signerStatuses);
export const duplicateSignerEmailMessage =
  "Each signer must have a unique email address.";
export const duplicateCopyRecipientEmailMessage =
  "This address is already a signer or a copy recipient.";

/** Someone who receives the finished document without signing it. */
export const copyRecipientSchema = z.object({
  id: idSchema.optional(),
  name: nameSchema,
  email: emailSchema,
});

export const draftSignerSchema = z.object({
  id: idSchema.optional(),
  envelopeId: idSchema.optional(),
  name: nameSchema,
  email: emailSchema,
  signOrder: z.number().int().positive().optional(),
  // Extra checks before signing. accessCode: a string sets it, null removes
  // it, and leaving it out keeps the code already saved.
  accessCode: z.string().trim().min(4).max(64).nullable().optional(),
  requireEmailCode: z.boolean().optional(),
  // What the signature means, for Part 11 envelopes. Null clears it, and
  // leaving it out keeps the one already saved.
  signatureMeaning: z.enum(signatureMeanings).nullable().optional(),
});

export const signerListSchema = z
  .array(draftSignerSchema)
  .min(1)
  .max(MAX_SIGNERS_PER_ENVELOPE)
  .superRefine((signers, ctx) => {
    const emails = new Set<string>();
    const signOrders = new Set<number>();

    for (const [index, signer] of signers.entries()) {
      const normalizedEmail = signer.email.toLowerCase();

      if (emails.has(normalizedEmail)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: duplicateSignerEmailMessage,
          path: [index, "email"],
        });
      }

      emails.add(normalizedEmail);

      if (signer.signOrder === undefined) {
        continue;
      }

      if (signOrders.has(signer.signOrder)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Each signer must have a unique routing order",
          path: [index, "signOrder"],
        });
      }

      signOrders.add(signer.signOrder);
    }
  });

export const replaceSignersSchema = z
  .object({
    // Left out keeps the copy recipients already saved.
    copyRecipients: z
      .array(copyRecipientSchema)
      .max(MAX_COPY_RECIPIENTS_PER_ENVELOPE)
      .optional(),
    signers: signerListSchema,
  })
  .superRefine((value, ctx) => {
    const emails = new Set(
      value.signers.map((signer) => signer.email.toLowerCase()),
    );

    for (const [index, recipient] of (value.copyRecipients ?? []).entries()) {
      const normalizedEmail = recipient.email.toLowerCase();

      if (emails.has(normalizedEmail)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: duplicateCopyRecipientEmailMessage,
          path: ["copyRecipients", index, "email"],
        });
      }

      emails.add(normalizedEmail);
    }
  });

export const replaceSignersResponseSchema = z.object({
  copyRecipients: z.array(
    z.object({ email: emailSchema, id: idSchema, name: nameSchema }),
  ),
  envelopeId: idSchema,
  redirectPath: z.string().trim().min(1),
  signers: z.array(
    z.object({
      email: emailSchema,
      id: idSchema,
      hasAccessCode: z.boolean(),
      name: nameSchema,
      requireEmailCode: z.boolean(),
      signatureMeaning: z.enum(signatureMeanings).nullable(),
      signOrder: z.number().int().positive(),
    }),
  ),
  updatedAt: unixTimestampSchema,
});

export const signerRecordSchema = draftSignerSchema.extend({
  status: signerStatusSchema,
  signingTokenExpiresAt: unixTimestampSchema.nullable().optional(),
  signingTokenHash: z.string().trim().length(64).nullable().optional(),
  turnStartedAt: unixTimestampSchema.nullable().optional(),
  lastNotifiedAt: unixTimestampSchema.nullable().optional(),
  lastNudgedAt: unixTimestampSchema.nullable().optional(),
  signedAt: unixTimestampSchema.nullable().optional(),
  declinedAt: unixTimestampSchema.nullable().optional(),
  declineReason: optionalTrimmedString(1000).nullable().optional(),
  createdAt: unixTimestampSchema,
  updatedAt: unixTimestampSchema,
});

export const declineEnvelopeSchema = z.object({
  reason: optionalTrimmedString(1000),
});

export const missingCorrectedSignerFieldsMessage =
  "Provide a name, an email address, or both.";

/** Name and/or email for a signer who has not signed or declined. */
export const correctSentSignerSchema = z
  .object({
    email: emailSchema.optional(),
    name: nameSchema.optional(),
  })
  .superRefine((value, ctx) => {
    if (value.email === undefined && value.name === undefined) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: missingCorrectedSignerFieldsMessage,
      });
    }
  });

export const correctSentSignerResponseSchema = z.object({
  email: emailSchema,
  envelopeId: idSchema,
  invitationSent: z.boolean(),
  name: nameSchema,
  signerId: idSchema,
});

export type CopyRecipient = z.infer<typeof copyRecipientSchema>;
/** A copy recipient as stored: it always has an id. */
export type CopyRecipientRecord = { email: string; id: string; name: string };
export type DraftSigner = z.infer<typeof draftSignerSchema>;
export type ReplaceSignersInput = z.infer<typeof replaceSignersSchema>;
export type ReplaceSignersResponse = z.infer<
  typeof replaceSignersResponseSchema
>;
export type SignerRecord = z.infer<typeof signerRecordSchema>;
export type DeclineEnvelopeInput = z.infer<typeof declineEnvelopeSchema>;
export type CorrectSentSignerInput = z.infer<typeof correctSentSignerSchema>;
export type CorrectSentSignerResponse = z.infer<
  typeof correctSentSignerResponseSchema
>;

import assert from "node:assert/strict";
import { test } from "node:test";
import { ZodError } from "zod";

import { describeSignerCorrectedEvent } from "./services/audit.ts";
import {
  correctSentSignerSchema,
  missingCorrectedSignerFieldsMessage,
} from "./schemas/signer.ts";

test("a signer correction needs a name, an email address, or both", () => {
  assert.deepEqual(correctSentSignerSchema.parse({ name: "Riley Recipient" }), {
    name: "Riley Recipient",
  });
  assert.deepEqual(
    correctSentSignerSchema.parse({ email: "riley@example.test" }),
    { email: "riley@example.test" },
  );
  assert.deepEqual(
    correctSentSignerSchema.parse({
      email: "riley@example.test",
      name: "Riley Recipient",
    }),
    { email: "riley@example.test", name: "Riley Recipient" },
  );

  try {
    correctSentSignerSchema.parse({});
    assert.fail("expected an empty correction to be refused");
  } catch (error) {
    assert.ok(error instanceof ZodError);
    assert.equal(error.issues[0]?.message, missingCorrectedSignerFieldsMessage);
  }

  assert.throws(
    () => correctSentSignerSchema.parse({ email: "not-an-email" }),
    ZodError,
  );
  assert.throws(() => correctSentSignerSchema.parse({ name: "   " }), ZodError);
});

test("a signer_corrected event is described in plain words", () => {
  assert.equal(
    describeSignerCorrectedEvent({
      previousEmail: "old@example.test",
      previousName: "Riley Recipient",
      signerEmail: "new@example.test",
      signerName: "Riley Recipient",
    }),
    "Signer email corrected from old@example.test to new@example.test",
  );
  assert.equal(
    describeSignerCorrectedEvent({
      previousEmail: "riley@example.test",
      previousName: "Rily",
      signerEmail: "riley@example.test",
      signerName: "Riley Recipient",
    }),
    "Signer name corrected from Rily to Riley Recipient",
  );
  assert.equal(
    describeSignerCorrectedEvent({
      previousEmail: "old@example.test",
      previousName: "Rily",
      signerEmail: "new@example.test",
      signerName: "Riley Recipient",
    }),
    "Signer corrected from Rily <old@example.test> to Riley Recipient <new@example.test>",
  );
  assert.equal(
    describeSignerCorrectedEvent({
      previousName: "Riley Recipient",
      signerName: "Riley Recipient",
    }),
    "Signer email was corrected",
  );
  assert.equal(
    describeSignerCorrectedEvent({
      previousName: "Rily",
      signerName: "Riley Recipient",
    }),
    "Signer name corrected from Rily to Riley Recipient",
  );
});

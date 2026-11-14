import { NextResponse } from "next/server";
import { ZodError } from "zod";

import { requireVerifiedSenderSession } from "@/lib/auth/route-session";
import { getDb } from "@/lib/db/connection";
import {
  correctSentEnvelopeSigner,
  EnvelopeMutationError,
} from "@/lib/envelopes";
import { logRouteError } from "@/lib/security/logging";
import {
  applyRateLimit,
  buildRateLimitKey,
} from "@/lib/security/route-controls";
import {
  getClientIpAddress,
  getRequestPathname,
  getRequestUserAgent,
} from "@/lib/security/request";

type EnvelopeSignerCorrectionRouteContext = {
  params: Promise<{
    id: string;
    signerId: string;
  }>;
};

const noStore = { "cache-control": "private, no-store" };

// Fixes the name and/or email of a signer who has not signed or declined
// on an envelope that is out for signature.
export async function PATCH(
  request: Request,
  context: EnvelopeSignerCorrectionRouteContext,
) {
  const sessionResult = await requireVerifiedSenderSession(request);

  if (sessionResult instanceof Response) {
    return sessionResult;
  }

  const session = sessionResult;
  const { id, signerId } = await context.params;
  const ipAddress = getClientIpAddress(request.headers);
  const rateLimitResponse = await applyRateLimit({
    category: "sent_envelope_signer_correct",
    key: buildRateLimitKey(["envelope-signer-correct", session.user.id, id]),
    limit: 20,
    request,
    userId: session.user.id,
    windowMs: 60 * 60 * 1000,
  });

  if (rateLimitResponse) {
    rateLimitResponse.headers.set("cache-control", "private, no-store");
    return rateLimitResponse;
  }

  const body = (await request.json().catch(() => null)) as unknown;

  try {
    const result = await correctSentEnvelopeSigner(
      session.user.id,
      id,
      signerId,
      body,
      {
        ipAddress,
        senderEmail: session.user.email,
        senderName:
          typeof session.user.name === "string" && session.user.name.trim()
            ? session.user.name
            : session.user.email,
        userAgent: getRequestUserAgent(request.headers),
      },
      { database: getDb() },
    );

    return NextResponse.json(result, { headers: noStore, status: 200 });
  } catch (error) {
    if (error instanceof ZodError) {
      const issue = error.issues[0];

      return NextResponse.json(
        { error: issue?.message ?? "Invalid signer correction." },
        { headers: noStore, status: 400 },
      );
    }

    if (error instanceof EnvelopeMutationError) {
      return NextResponse.json(
        { error: error.message },
        { headers: noStore, status: error.statusCode },
      );
    }

    logRouteError(error, {
      category: "sent_envelope_signer_correct_failure",
      ipAddress,
      message: "Unexpected failure while correcting a signer.",
      path: getRequestPathname(request),
      userId: session.user.id,
    });

    return NextResponse.json(
      { error: "Unable to correct this signer." },
      { headers: noStore, status: 500 },
    );
  }
}

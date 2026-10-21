import { parseBetaSignup, RateLimiter } from "@/lib/beta";

// 5 inscriptions par adresse IP et par 10 minutes.
const limiter = new RateLimiter(5, 10 * 60 * 1000);

function json(body: unknown, status: number) {
  return Response.json(body, { status, headers: { "Cache-Control": "no-store" } });
}

export async function POST(request: Request): Promise<Response> {
  const ip = request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || "inconnu";
  if (!limiter.allow(ip)) return json({ error: "rate_limited" }, 429);

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return json({ error: "invalid_json" }, 400);
  }

  const parsed = parseBetaSignup(body);
  if (!parsed.ok) {
    if ("spam" in parsed) return json({ ok: true }, 200);
    return json({ error: "invalid", fields: parsed.errors }, 400);
  }

  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !key) return json({ error: "not_configured" }, 503);

  const res = await fetch(`${url}/rest/v1/beta_signups?on_conflict=email`, {
    method: "POST",
    headers: {
      apikey: key,
      Authorization: `Bearer ${key}`,
      "Content-Type": "application/json",
      // Un e-mail déjà inscrit n'est pas une erreur, et ne doit pas se distinguer
      // d'une nouvelle inscription (pas d'énumération des inscrits).
      Prefer: "resolution=ignore-duplicates,return=minimal",
    },
    body: JSON.stringify({ ...parsed.data, consent_at: new Date().toISOString() }),
  });
  if (!res.ok) {
    console.error("inscription bêta : Supabase a répondu", res.status);
    return json({ error: "storage_failed" }, 502);
  }
  return json({ ok: true }, 201);
}

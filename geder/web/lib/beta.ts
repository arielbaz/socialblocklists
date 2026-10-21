// Validation des inscriptions bêta, partagée par la route serveur et ses tests.
// Les contraintes reprennent celles de la table public.beta_signups.

export const COUNTRIES = ["FR", "IL", "BE", "CH", "CA", "US", "GB", "other"] as const;
export const AUDIENCES = ["family", "personal", "institution"] as const;
export const LOCALES = ["fr", "he"] as const;

export type Country = (typeof COUNTRIES)[number];
export type Audience = (typeof AUDIENCES)[number];
export type Locale = (typeof LOCALES)[number];

export type BetaSignup = {
  email: string;
  name: string | null;
  country: Country;
  audience: Audience;
  devices: number | null;
  community: string | null;
  locale: Locale;
};

export type FieldError = "email" | "name" | "country" | "audience" | "devices" | "community" | "consent";

export type ParseResult =
  | { ok: true; data: BetaSignup }
  | { ok: false; errors: FieldError[] }
  /** Champ piège rempli : un robot. On répond comme un succès sans rien enregistrer. */
  | { ok: false; spam: true };

const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

function optionalText(value: unknown, max: number): string | null | undefined {
  if (value === undefined || value === null) return null;
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  if (trimmed.length === 0) return null;
  return trimmed.length <= max ? trimmed : undefined;
}

function oneOf<T extends string>(list: readonly T[], value: unknown): value is T {
  return typeof value === "string" && (list as readonly string[]).includes(value);
}

export function parseBetaSignup(input: unknown): ParseResult {
  if (typeof input !== "object" || input === null) return { ok: false, errors: ["email"] };
  const body = input as Record<string, unknown>;

  if (typeof body.website === "string" && body.website.trim() !== "") {
    return { ok: false, spam: true };
  }

  const errors: FieldError[] = [];

  const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
  if (email.length > 254 || !EMAIL_RE.test(email)) errors.push("email");

  const name = optionalText(body.name, 120);
  if (name === undefined) errors.push("name");

  if (!oneOf(COUNTRIES, body.country)) errors.push("country");
  if (!oneOf(AUDIENCES, body.audience)) errors.push("audience");

  let devices: number | null = null;
  if (body.devices !== undefined && body.devices !== null && body.devices !== "") {
    const n = typeof body.devices === "number" ? body.devices : Number(body.devices);
    if (Number.isInteger(n) && n >= 1 && n <= 5000) devices = n;
    else errors.push("devices");
  }

  const community = optionalText(body.community, 200);
  if (community === undefined) errors.push("community");

  if (body.consent !== true) errors.push("consent");

  const locale: Locale = oneOf(LOCALES, body.locale) ? body.locale : "fr";

  if (errors.length > 0) return { ok: false, errors };
  return {
    ok: true,
    data: {
      email,
      name: name ?? null,
      country: body.country as Country,
      audience: body.audience as Audience,
      devices,
      community: community ?? null,
      locale,
    },
  };
}

/** Limiteur de débit en mémoire, par clé (adresse IP). Au mieux : une instance serveur. */
export class RateLimiter {
  private hits = new Map<string, number[]>();

  constructor(
    private readonly max: number,
    private readonly windowMs: number,
  ) {}

  allow(key: string, now: number = Date.now()): boolean {
    const recent = (this.hits.get(key) ?? []).filter((t) => now - t < this.windowMs);
    if (recent.length >= this.max) {
      this.hits.set(key, recent);
      return false;
    }
    recent.push(now);
    this.hits.set(key, recent);
    if (this.hits.size > 10_000) this.prune(now);
    return true;
  }

  private prune(now: number) {
    for (const [key, times] of this.hits) {
      if (times.every((t) => now - t >= this.windowMs)) this.hits.delete(key);
    }
  }
}

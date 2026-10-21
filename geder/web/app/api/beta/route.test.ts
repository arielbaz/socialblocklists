import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const body = {
  email: "parent@exemple.fr",
  country: "IL",
  audience: "family",
  consent: true,
  locale: "he",
};

function post(data: unknown, ip = "203.0.113.1") {
  return new Request("http://localhost/api/beta", {
    method: "POST",
    headers: { "Content-Type": "application/json", "x-forwarded-for": ip },
    body: typeof data === "string" ? data : JSON.stringify(data),
  });
}

// Le module garde son limiteur en mémoire : on le recharge à chaque test.
async function route() {
  vi.resetModules();
  return (await import("./route")).POST;
}

describe("POST /api/beta", () => {
  beforeEach(() => {
    vi.stubEnv("SUPABASE_URL", "https://projet.supabase.co");
    vi.stubEnv("SUPABASE_SERVICE_ROLE_KEY", "cle-service");
  });
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
  });

  it("enregistre dans Supabase sans doublon visible", async () => {
    const fetchMock = vi.fn(async () => new Response(null, { status: 201 }));
    vi.stubGlobal("fetch", fetchMock);
    const res = await (await route())(post(body));
    expect(res.status).toBe(201);

    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("https://projet.supabase.co/rest/v1/beta_signups?on_conflict=email");
    const headers = init.headers as Record<string, string>;
    expect(headers.Authorization).toBe("Bearer cle-service");
    expect(headers.Prefer).toContain("resolution=ignore-duplicates");
    const sent = JSON.parse(init.body as string);
    expect(sent).toMatchObject({ email: "parent@exemple.fr", country: "IL", locale: "he" });
    expect(Date.parse(sent.consent_at)).not.toBeNaN();
    expect(sent).not.toHaveProperty("consent");
  });

  it("renvoie les champs invalides sans appeler Supabase", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const res = await (await route())(post({ ...body, email: "x" }));
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "invalid", fields: ["email"] });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("fait semblant d'accepter les robots", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const res = await (await route())(post({ ...body, website: "spam" }));
    expect(res.status).toBe(200);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("refuse le JSON invalide", async () => {
    const res = await (await route())(post("{pas du json"));
    expect(res.status).toBe(400);
  });

  it("limite le débit par adresse IP", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(null, { status: 201 })));
    const POST = await route();
    for (let i = 0; i < 5; i++) expect((await POST(post(body))).status).toBe(201);
    expect((await POST(post(body))).status).toBe(429);
    expect((await POST(post(body, "198.51.100.7"))).status).toBe(201);
  });

  it("503 si Supabase n'est pas configuré", async () => {
    vi.unstubAllEnvs();
    vi.stubEnv("SUPABASE_URL", "");
    const res = await (await route())(post(body));
    expect(res.status).toBe(503);
  });

  it("502 si Supabase échoue", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("boom", { status: 500 })));
    vi.spyOn(console, "error").mockImplementation(() => {});
    const res = await (await route())(post(body));
    expect(res.status).toBe(502);
  });
});

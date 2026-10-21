import { describe, expect, it } from "vitest";
import { parseBetaSignup, RateLimiter } from "./beta";

const valid = {
  email: "  Famille@Exemple.FR ",
  name: "Famille Levy",
  country: "FR",
  audience: "family",
  devices: "3",
  community: "Sarcelles",
  consent: true,
  locale: "fr",
};

describe("parseBetaSignup", () => {
  it("normalise une inscription valide", () => {
    const r = parseBetaSignup(valid);
    expect(r).toEqual({
      ok: true,
      data: {
        email: "famille@exemple.fr",
        name: "Famille Levy",
        country: "FR",
        audience: "family",
        devices: 3,
        community: "Sarcelles",
        locale: "fr",
      },
    });
  });

  it("accepte les champs facultatifs vides", () => {
    const r = parseBetaSignup({ ...valid, name: "", devices: "", community: "   " });
    expect(r.ok && r.data).toMatchObject({ name: null, devices: null, community: null });
  });

  it("signale chaque champ invalide", () => {
    const r = parseBetaSignup({
      email: "pas-un-email",
      name: "x".repeat(121),
      country: "XX",
      audience: "tout le monde",
      devices: "2.5",
      community: 42,
      consent: "oui",
    });
    expect(r).toEqual({
      ok: false,
      errors: ["email", "name", "country", "audience", "devices", "community", "consent"],
    });
  });

  it("exige un consentement explicite", () => {
    expect(parseBetaSignup({ ...valid, consent: undefined })).toEqual({ ok: false, errors: ["consent"] });
  });

  it("repère le champ piège des robots", () => {
    expect(parseBetaSignup({ ...valid, website: "http://spam.example" })).toEqual({ ok: false, spam: true });
  });

  it("langue inconnue : français par défaut", () => {
    const r = parseBetaSignup({ ...valid, locale: "de" });
    expect(r.ok && r.data.locale).toBe("fr");
  });

  it("refuse une entrée qui n'est pas un objet", () => {
    expect(parseBetaSignup(null).ok).toBe(false);
    expect(parseBetaSignup("x").ok).toBe(false);
  });
});

describe("RateLimiter", () => {
  it("limite par clé et par fenêtre", () => {
    const l = new RateLimiter(2, 1000);
    expect(l.allow("a", 0)).toBe(true);
    expect(l.allow("a", 10)).toBe(true);
    expect(l.allow("a", 20)).toBe(false);
    expect(l.allow("b", 20)).toBe(true);
    expect(l.allow("a", 1010)).toBe(true);
  });
});

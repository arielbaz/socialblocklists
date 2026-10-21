"use client";

import { useState, type FormEvent } from "react";
import { AUDIENCES, COUNTRIES, type FieldError, type Locale } from "@/lib/beta";
import type { Dictionary } from "@/lib/i18n";

type Status = { kind: "idle" } | { kind: "sending" } | { kind: "done" } | { kind: "error"; message: string };

export default function BetaForm({ locale, t }: { locale: Locale; t: Dictionary["form"] }) {
  const [status, setStatus] = useState<Status>({ kind: "idle" });
  const [fieldErrors, setFieldErrors] = useState<FieldError[]>([]);

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    setStatus({ kind: "sending" });
    setFieldErrors([]);
    const body = {
      email: form.get("email"),
      name: form.get("name"),
      country: form.get("country"),
      audience: form.get("audience"),
      devices: form.get("devices"),
      community: form.get("community"),
      consent: form.get("consent") === "on",
      website: form.get("website"),
      locale,
    };
    try {
      const res = await fetch("/api/beta", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (res.ok) {
        setStatus({ kind: "done" });
        return;
      }
      const data = (await res.json().catch(() => ({}))) as { error?: string; fields?: FieldError[] };
      if (res.status === 400 && data.fields) {
        setFieldErrors(data.fields);
        setStatus({ kind: "error", message: data.fields.map((f) => t.errors[f]).join(" ") });
      } else if (res.status === 429) {
        setStatus({ kind: "error", message: t.errors.rateLimited });
      } else if (res.status === 503) {
        setStatus({ kind: "error", message: t.errors.unavailable });
      } else {
        setStatus({ kind: "error", message: t.errors.generic });
      }
    } catch {
      setStatus({ kind: "error", message: t.errors.generic });
    }
  }

  if (status.kind === "done") {
    return (
      <p className="notice notice-ok" role="status">
        {t.success}
      </p>
    );
  }

  const invalid = (f: FieldError) => (fieldErrors.includes(f) ? true : undefined);

  return (
    <form className="form" onSubmit={onSubmit} noValidate>
      <label>
        {t.email}
        <input name="email" type="email" autoComplete="email" required maxLength={254} aria-invalid={invalid("email")} />
      </label>
      <label>
        {t.name}
        <input name="name" type="text" autoComplete="name" maxLength={120} aria-invalid={invalid("name")} />
      </label>
      <div className="form-row">
        <label>
          {t.country}
          <select name="country" required defaultValue={locale === "he" ? "IL" : "FR"} aria-invalid={invalid("country")}>
            {COUNTRIES.map((c) => (
              <option key={c} value={c}>
                {t.countries[c]}
              </option>
            ))}
          </select>
        </label>
        <label>
          {t.devices}
          <input name="devices" type="number" inputMode="numeric" min={1} max={5000} aria-invalid={invalid("devices")} />
        </label>
      </div>
      <fieldset aria-invalid={invalid("audience")}>
        <legend>{t.audience}</legend>
        <div className="choices">
          {AUDIENCES.map((a, i) => (
            <label className="choice" key={a}>
              <input type="radio" name="audience" value={a} defaultChecked={i === 0} />
              {t.audiences[a]}
            </label>
          ))}
        </div>
      </fieldset>
      <label>
        {t.community}
        <input name="community" type="text" maxLength={200} aria-describedby="community-hint" aria-invalid={invalid("community")} />
        <span id="community-hint" className="hint">
          {t.communityHint}
        </span>
      </label>
      {/* Champ piège invisible : seuls les robots le remplissent. */}
      <div className="trap" aria-hidden="true">
        <label>
          Website
          <input name="website" type="text" tabIndex={-1} autoComplete="off" />
        </label>
      </div>
      <label className="choice consent">
        <input name="consent" type="checkbox" required aria-invalid={invalid("consent")} />
        {t.consent}
      </label>
      <button className="button" type="submit" disabled={status.kind === "sending"}>
        {status.kind === "sending" ? t.sending : t.submit}
      </button>
      {status.kind === "error" && (
        <p className="notice notice-error" role="alert">
          {status.message}
        </p>
      )}
    </form>
  );
}

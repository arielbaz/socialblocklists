import { notFound } from "next/navigation";
import BetaForm from "@/components/BetaForm";
import { LOCALES, type Locale } from "@/lib/beta";
import { dictionaries } from "@/lib/i18n";

export default async function Home({ params }: { params: Promise<{ lang: string }> }) {
  const { lang } = await params;
  if (!(LOCALES as readonly string[]).includes(lang)) notFound();
  const locale = lang as Locale;
  const t = dictionaries[locale];

  return (
    <>
      <header className="topbar">
        <div className="wrap topbar-inner">
          <a className="brand" href={`/${locale}`}>
            <span className="brand-mark" aria-hidden="true" />
            GEDER
          </a>
          <nav className="topnav">
            <a href={t.nav.otherHref} lang={locale === "fr" ? "he" : "fr"}>
              {t.nav.otherLang}
            </a>
            <a className="button button-small" href="#beta">
              {t.nav.cta}
            </a>
          </nav>
        </div>
      </header>

      <main>
        <section className="hero">
          <div className="wrap">
            <h1>{t.hero.title}</h1>
            <p className="lead">{t.hero.lead}</p>
            <a className="button" href="#beta">
              {t.hero.cta}
            </a>
            <p className="hero-note">{t.hero.note}</p>
          </div>
        </section>

        <section className="wrap section" aria-labelledby="pillars">
          <h2 id="pillars">{t.pillars.title}</h2>
          <div className="grid grid-4">
            {t.pillars.items.map((p) => (
              <article className="card" key={p.title}>
                <h3>{p.title}</h3>
                <p>{p.text}</p>
              </article>
            ))}
          </div>
        </section>

        <section className="wrap section" aria-labelledby="steps">
          <h2 id="steps">{t.steps.title}</h2>
          <ol className="steps">
            {t.steps.items.map((s) => (
              <li key={s.title}>
                <h3>{s.title}</h3>
                <p>{s.text}</p>
              </li>
            ))}
          </ol>
        </section>

        <section className="wrap section" aria-labelledby="offers">
          <h2 id="offers">{t.offers.title}</h2>
          <div className="grid grid-3">
            {t.offers.items.map((o) => (
              <article className="card" key={o.name}>
                <h3>{o.name}</h3>
                <p className="muted">{o.who}</p>
                <p>{o.text}</p>
              </article>
            ))}
          </div>
          <p className="muted section-note">{t.offers.note}</p>
        </section>

        <section className="wrap section" aria-labelledby="faq">
          <h2 id="faq">{t.faq.title}</h2>
          <div className="faq">
            {t.faq.items.map((f) => (
              <details key={f.q}>
                <summary>{f.q}</summary>
                <p>{f.a}</p>
              </details>
            ))}
          </div>
        </section>

        <section className="wrap section" id="beta" aria-labelledby="beta-title">
          <div className="panel">
            <h2 id="beta-title">{t.form.title}</h2>
            <p>{t.form.lead}</p>
            <BetaForm locale={locale} t={t.form} />
          </div>
        </section>
      </main>

      <footer className="footer">
        <div className="wrap">
          <p>{t.footer.line}</p>
          <p className="muted">{t.footer.privacy}</p>
        </div>
      </footer>
    </>
  );
}

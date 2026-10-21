import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { LOCALES, type Locale } from "@/lib/beta";
import { dictionaries } from "@/lib/i18n";
import "../globals.css";

export function generateStaticParams() {
  return LOCALES.map((lang) => ({ lang }));
}

export const dynamicParams = false;

function isLocale(value: string): value is Locale {
  return (LOCALES as readonly string[]).includes(value);
}

export async function generateMetadata({ params }: { params: Promise<{ lang: string }> }): Promise<Metadata> {
  const { lang } = await params;
  if (!isLocale(lang)) return {};
  const t = dictionaries[lang];
  return {
    title: t.meta.title,
    description: t.meta.description,
    alternates: { languages: { fr: "/fr", he: "/he" } },
  };
}

export default async function LangLayout({
  children,
  params,
}: {
  children: React.ReactNode;
  params: Promise<{ lang: string }>;
}) {
  const { lang } = await params;
  if (!isLocale(lang)) notFound();
  return (
    <html lang={lang} dir={dictionaries[lang].dir}>
      <body>{children}</body>
    </html>
  );
}

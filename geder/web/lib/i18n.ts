// Textes du site. L'hébreu est une première traduction : à faire relire par un
// locuteur natif avant la mise en ligne.

import type { Audience, Country, FieldError, Locale } from "./beta";

export type Dictionary = {
  dir: "ltr" | "rtl";
  meta: { title: string; description: string };
  nav: { otherLang: string; otherHref: string; cta: string };
  hero: { title: string; lead: string; cta: string; note: string };
  pillars: { title: string; items: { title: string; text: string }[] };
  steps: { title: string; items: { title: string; text: string }[] };
  offers: { title: string; note: string; items: { name: string; who: string; text: string }[] };
  faq: { title: string; items: { q: string; a: string }[] };
  form: {
    title: string;
    lead: string;
    email: string;
    name: string;
    country: string;
    countries: Record<Country, string>;
    audience: string;
    audiences: Record<Audience, string>;
    devices: string;
    community: string;
    communityHint: string;
    consent: string;
    submit: string;
    sending: string;
    success: string;
    errors: Record<FieldError, string> & { generic: string; rateLimited: string; unavailable: string };
  };
  footer: { line: string; privacy: string };
};

const fr: Dictionary = {
  dir: "ltr",
  meta: {
    title: "GEDER — un Internet propre, sur tous les appareils de la maison",
    description:
      "Filtre Internet en liste blanche, impossible à contourner ni à désinstaller, qui fonctionne sur l'appareil sans faire passer votre navigation par nos serveurs.",
  },
  nav: { otherLang: "עברית", otherHref: "/he", cta: "Rejoindre la bêta" },
  hero: {
    title: "Un Internet propre, sur tous les appareils de la maison.",
    lead:
      "GEDER ne laisse passer que les sites autorisés. Le filtre tourne sur l'appareil lui-même : votre navigation ne passe par aucun serveur, chez nous ou ailleurs.",
    cta: "Rejoindre la bêta",
    note: "Android et ordinateurs Windows pour la bêta. iPhone et Mac ensuite.",
  },
  pillars: {
    title: "Pourquoi GEDER",
    items: [
      {
        title: "Une liste blanche hermétique",
        text: "Tout ce qui n'est pas autorisé est bloqué, y compris les contournements connus : VPN, DNS chiffré, navigateurs à proxy, adresses codées en dur.",
      },
      {
        title: "Impossible à désinstaller",
        text: "Sur Android, GEDER devient l'administrateur du téléphone : ni désinstallation, ni réinitialisation, ni mode sans échec sans votre accord.",
      },
      {
        title: "Votre vie privée reste chez vous",
        text: "Le filtrage se fait sur l'appareil. Nous ne recevons que les demandes d'ouverture que vous choisissez d'envoyer.",
      },
      {
        title: "Une équipe qui répond",
        text: "Un site utile est bloqué ? Une demande en un clic, traitée par notre équipe de filtrage, rapidement et selon une charte écrite.",
      },
    ],
  },
  steps: {
    title: "Comment se passe la bêta",
    items: [
      { title: "Vous vous inscrivez", text: "En deux minutes, avec ce formulaire." },
      { title: "Nous installons GEDER avec vous", text: "Sur vos téléphones Android et vos ordinateurs Windows, à distance ou sur place." },
      { title: "Vous gardez la main", text: "Appareils, demandes d'ouverture, horaires : tout se gère depuis votre console." },
    ],
  },
  offers: {
    title: "Pour qui",
    note: "Les participants à la bêta testent gratuitement. Les tarifs seront annoncés à l'ouverture.",
    items: [
      { name: "Famille", who: "Jusqu'à 5 appareils", text: "Une console pour les parents, les demandes de chacun au même endroit." },
      { name: "Personnel", who: "Un adulte et son tiers de confiance", text: "Le code est détenu par un conjoint, un Rav ou un ami : vous seul ne pouvez pas l'enlever." },
      { name: "Institution", who: "Écoles, yeshivot, entreprises", text: "Une licence par poste et plusieurs administrateurs." },
    ],
  },
  faq: {
    title: "Questions fréquentes",
    items: [
      {
        q: "Voyez-vous les sites que je visite ?",
        a: "Non. Le filtre décide sur votre appareil. Votre historique n'est envoyé nulle part ; seules les demandes d'ouverture que vous envoyez nous parviennent.",
      },
      {
        q: "Faut-il réinitialiser le téléphone ?",
        a: "Pour la protection complète sur Android, oui : GEDER s'installe au premier démarrage du téléphone. Nous vous accompagnons, et nous sauvegardons vos données avant.",
      },
      {
        q: "Et si un site dont j'ai besoin est bloqué ?",
        a: "Vous demandez son ouverture en un clic depuis l'appareil. Notre équipe vérifie le site et l'ouvre pour votre foyer, ou pour tous.",
      },
      {
        q: "Quels appareils sont pris en charge ?",
        a: "Pour la bêta : téléphones et tablettes Android, ordinateurs Windows, navigateurs Chrome et Edge. iPhone, iPad et Mac arrivent ensuite.",
      },
    ],
  },
  form: {
    title: "Rejoindre la bêta",
    lead: "Nous ouvrons la bêta par petits groupes. Laissez-nous vos coordonnées : nous vous écrivons dès qu'une place se libère.",
    email: "Adresse e-mail",
    name: "Nom (facultatif)",
    country: "Pays",
    countries: {
      FR: "France",
      IL: "Israël",
      BE: "Belgique",
      CH: "Suisse",
      CA: "Canada",
      US: "États-Unis",
      GB: "Royaume-Uni",
      other: "Autre",
    },
    audience: "Pour",
    audiences: { family: "Ma famille", personal: "Moi-même", institution: "Une institution" },
    devices: "Nombre d'appareils (facultatif)",
    community: "Communauté, école ou ville (facultatif)",
    communityHint: "Cela nous aide à organiser les groupes de la bêta.",
    consent: "J'accepte que GEDER m'écrive au sujet de la bêta. Mon adresse ne sera ni vendue ni partagée.",
    submit: "M'inscrire",
    sending: "Envoi…",
    success: "Merci ! Vous êtes inscrit. Nous vous écrivons dès qu'une place se libère.",
    errors: {
      email: "Adresse e-mail invalide.",
      name: "Nom trop long.",
      country: "Choisissez un pays.",
      audience: "Choisissez pour qui.",
      devices: "Nombre d'appareils invalide.",
      community: "Texte trop long.",
      consent: "Merci de cocher la case d'accord.",
      generic: "L'inscription n'a pas abouti. Réessayez dans un instant.",
      rateLimited: "Trop d'essais. Réessayez dans quelques minutes.",
      unavailable: "Les inscriptions ouvrent très bientôt. Revenez dans quelques jours.",
    },
  },
  footer: {
    line: "GEDER est un projet d'Aribaz.",
    privacy: "Votre adresse sert uniquement à la bêta. Pour être retiré de la liste, répondez simplement à l'un de nos e-mails.",
  },
};

const he: Dictionary = {
  dir: "rtl",
  meta: {
    title: "גדר — אינטרנט נקי בכל המכשירים בבית",
    description:
      "סינון אינטרנט ברשימה לבנה, שאי אפשר לעקוף ואי אפשר להסיר, הפועל על המכשיר עצמו בלי להעביר את הגלישה שלכם דרך השרתים שלנו.",
  },
  nav: { otherLang: "Français", otherHref: "/fr", cta: "להצטרפות לבטא" },
  hero: {
    title: "אינטרנט נקי, בכל המכשירים בבית.",
    lead: "גדר מאפשר גישה רק לאתרים מאושרים. הסינון פועל על המכשיר עצמו: הגלישה שלכם לא עוברת דרך שום שרת, לא אצלנו ולא במקום אחר.",
    cta: "להצטרפות לבטא",
    note: "בשלב הבטא: אנדרואיד ומחשבי Windows. אייפון ומק בהמשך.",
  },
  pillars: {
    title: "למה גדר",
    items: [
      {
        title: "רשימה לבנה הרמטית",
        text: "כל מה שלא אושר — חסום, כולל דרכי העקיפה המוכרות: VPN, DNS מוצפן, דפדפנים עם פרוקסי וכתובות מקודדות.",
      },
      {
        title: "אי אפשר להסיר",
        text: "באנדרואיד, גדר הופך למנהל המכשיר: אין הסרה, אין איפוס ואין מצב בטוח בלי אישורכם.",
      },
      {
        title: "הפרטיות נשארת אצלכם",
        text: "הסינון מתבצע על המכשיר. אנחנו מקבלים רק את בקשות הפתיחה שאתם בוחרים לשלוח.",
      },
      {
        title: "צוות שעונה",
        text: "אתר נחוץ חסום? בקשה בלחיצה אחת, שמטופלת על ידי צוות הסינון שלנו, במהירות ולפי מדיניות כתובה.",
      },
    ],
  },
  steps: {
    title: "איך עובדת הבטא",
    items: [
      { title: "נרשמים", text: "שתי דקות, בטופס הזה." },
      { title: "מתקינים יחד איתכם", text: "בטלפונים האנדרואיד ובמחשבי ה-Windows שלכם, מרחוק או אצלכם." },
      { title: "השליטה בידיים שלכם", text: "מכשירים, בקשות פתיחה ושעות — הכול מנוהל מלוח הבקרה שלכם." },
    ],
  },
  offers: {
    title: "למי זה מתאים",
    note: "משתתפי הבטא בודקים ללא תשלום. המחירים יפורסמו בפתיחה.",
    items: [
      { name: "משפחה", who: "עד 5 מכשירים", text: "לוח בקרה להורים, וכל הבקשות במקום אחד." },
      { name: "אישי", who: "מבוגר ואדם שהוא סומך עליו", text: "הקוד נמצא אצל בן או בת הזוג, רב או חבר: אי אפשר להסיר לבד." },
      { name: "מוסד", who: "בתי ספר, ישיבות, עסקים", text: "רישיון לכל עמדה וכמה מנהלים." },
    ],
  },
  faq: {
    title: "שאלות נפוצות",
    items: [
      {
        q: "האם אתם רואים באילו אתרים אני גולש?",
        a: "לא. הסינון מחליט על המכשיר שלכם. היסטוריית הגלישה לא נשלחת לשום מקום; רק בקשות הפתיחה שאתם שולחים מגיעות אלינו.",
      },
      {
        q: "צריך לאפס את הטלפון?",
        a: "להגנה מלאה באנדרואיד, כן: גדר מותקן בהפעלה הראשונה של הטלפון. אנחנו מלווים אתכם ומגבים את הנתונים לפני כן.",
      },
      {
        q: "ומה אם אתר שאני צריך חסום?",
        a: "מבקשים לפתוח אותו בלחיצה מהמכשיר. הצוות שלנו בודק את האתר ופותח אותו לבית שלכם, או לכולם.",
      },
      {
        q: "אילו מכשירים נתמכים?",
        a: "בבטא: טלפונים וטאבלטים אנדרואיד, מחשבי Windows, ודפדפני Chrome ו-Edge. אייפון, אייפד ומק בהמשך.",
      },
    ],
  },
  form: {
    title: "להצטרפות לבטא",
    lead: "אנחנו פותחים את הבטא בקבוצות קטנות. השאירו פרטים ונכתוב לכם ברגע שיתפנה מקום.",
    email: "כתובת אימייל",
    name: "שם (לא חובה)",
    country: "מדינה",
    countries: {
      FR: "צרפת",
      IL: "ישראל",
      BE: "בלגיה",
      CH: "שווייץ",
      CA: "קנדה",
      US: "ארצות הברית",
      GB: "בריטניה",
      other: "אחר",
    },
    audience: "עבור",
    audiences: { family: "המשפחה שלי", personal: "עצמי", institution: "מוסד" },
    devices: "מספר מכשירים (לא חובה)",
    community: "קהילה, מוסד או עיר (לא חובה)",
    communityHint: "זה עוזר לנו לארגן את קבוצות הבטא.",
    consent: "אני מסכים/ה שגדר יכתבו לי בנוגע לבטא. הכתובת שלי לא תימכר ולא תועבר.",
    submit: "להרשמה",
    sending: "שולח…",
    success: "תודה! נרשמתם. נכתוב לכם ברגע שיתפנה מקום.",
    errors: {
      email: "כתובת אימייל לא תקינה.",
      name: "השם ארוך מדי.",
      country: "יש לבחור מדינה.",
      audience: "יש לבחור עבור מי.",
      devices: "מספר מכשירים לא תקין.",
      community: "הטקסט ארוך מדי.",
      consent: "יש לסמן את תיבת ההסכמה.",
      generic: "ההרשמה לא הצליחה. נסו שוב בעוד רגע.",
      rateLimited: "יותר מדי ניסיונות. נסו שוב בעוד כמה דקות.",
      unavailable: "ההרשמה תיפתח בקרוב מאוד. חזרו בעוד כמה ימים.",
    },
  },
  footer: {
    line: "גדר הוא פרויקט של Aribaz.",
    privacy: "הכתובת שלכם משמשת רק לבטא. כדי להסיר אותה מהרשימה, פשוט השיבו לאחד המיילים שלנו.",
  },
};

export const dictionaries: Record<Locale, Dictionary> = { fr, he };

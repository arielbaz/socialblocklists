//! Listes blanches signées.
//!
//! Format texte, une règle par ligne, signé par le serveur avec Ed25519 :
//!
//! ```text
//! !geder-list 1
//! !name base-fr
//! !version 2026102101
//! # commentaire
//! impots.gouv.fr
//! *.impots.gouv.fr
//! !signature ed25519:<base64>
//! ```
//!
//! La signature couvre tous les octets qui précèdent la ligne `!signature`.
//! Une liste non signée, mal signée ou plus ancienne que celle déjà chargée est
//! refusée : sinon quiconque intercepte une mise à jour pourrait ouvrir tout Internet.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::domain::{DomainError, Rule};

const MAGIC: &str = "!geder-list 1";
const SIG_PREFIX: &str = "!signature ed25519:";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowList {
    pub name: String,
    pub version: u64,
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ListError {
    #[error("la liste n'est pas en UTF-8")]
    NotUtf8,
    #[error("en-tête `{MAGIC}` absent")]
    MissingMagic,
    #[error("ligne {line} : directive inconnue ou mal formée")]
    BadDirective { line: usize },
    #[error("ligne {line} : {source}")]
    BadRule { line: usize, source: DomainError },
    #[error("directive `!name` absente ou invalide")]
    MissingName,
    #[error("directive `!version` absente")]
    MissingVersion,
    #[error("signature absente")]
    MissingSignature,
    #[error("contenu après la ligne de signature")]
    TrailingData,
    #[error("signature invalide")]
    BadSignature,
}

/// Analyse une liste sans vérifier de signature (outil serveur uniquement).
/// Une éventuelle ligne `!signature` finale est ignorée.
pub fn parse_unsigned(text: &str) -> Result<AllowList, ListError> {
    let (body, _) = split_signature(text);
    parse_body(body)
}

/// Vérifie la signature avec l'une des clés de confiance puis analyse la liste.
/// Plusieurs clés permettent la rotation : ancienne et nouvelle clé coexistent un temps.
pub fn verify(data: &[u8], trusted: &[VerifyingKey]) -> Result<AllowList, ListError> {
    let text = std::str::from_utf8(data).map_err(|_| ListError::NotUtf8)?;
    let (body, sig_line) = split_signature(text);
    let sig_line = sig_line.ok_or(ListError::MissingSignature)?;
    let sig_b64 = sig_line.trim_end_matches(['\r', '\n']).strip_prefix(SIG_PREFIX).ok_or(ListError::BadSignature)?;
    if sig_b64.contains('\n') {
        return Err(ListError::TrailingData);
    }
    let sig_bytes = B64.decode(sig_b64.trim()).map_err(|_| ListError::BadSignature)?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|_| ListError::BadSignature)?;
    if !trusted.iter().any(|k| k.verify_strict(body.as_bytes(), &sig).is_ok()) {
        return Err(ListError::BadSignature);
    }
    parse_body(body)
}

/// Valide la liste puis la renvoie signée (toute signature précédente est remplacée).
pub fn sign(text: &str, key: &SigningKey) -> Result<String, ListError> {
    let (body, _) = split_signature(text);
    parse_body(body)?;
    let mut out = body.to_owned();
    if !out.ends_with('\n') {
        out.push('\n');
    }
    let sig = key.sign(out.as_bytes());
    out.push_str(SIG_PREFIX);
    out.push_str(&B64.encode(sig.to_bytes()));
    out.push('\n');
    Ok(out)
}

/// Sépare le corps signé de la ligne `!signature` (et de ce qui la suit).
fn split_signature(text: &str) -> (&str, Option<&str>) {
    if text.starts_with(SIG_PREFIX) {
        return ("", Some(text));
    }
    match text.find(&format!("\n{SIG_PREFIX}")) {
        Some(i) => (&text[..i + 1], Some(&text[i + 1..])),
        None => (text, None),
    }
}

fn parse_body(body: &str) -> Result<AllowList, ListError> {
    let mut lines = body.lines().enumerate();
    match lines.next() {
        Some((_, l)) if l.trim_end() == MAGIC => {}
        _ => return Err(ListError::MissingMagic),
    }
    let mut name = None;
    let mut version = None;
    let mut rules = Vec::new();
    for (i, raw) in lines {
        let line = i + 1;
        let l = raw.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        if let Some(directive) = l.strip_prefix('!') {
            let (key, value) = directive.split_once(' ').ok_or(ListError::BadDirective { line })?;
            match key {
                "name" if is_valid_name(value) && name.is_none() => name = Some(value.to_owned()),
                "version" if version.is_none() => {
                    version = Some(value.parse::<u64>().map_err(|_| ListError::BadDirective { line })?)
                }
                _ => return Err(ListError::BadDirective { line }),
            }
            continue;
        }
        rules.push(Rule::parse(l).map_err(|source| ListError::BadRule { line, source })?);
    }
    Ok(AllowList {
        name: name.ok_or(ListError::MissingName)?,
        version: version.ok_or(ListError::MissingVersion)?,
        rules,
    })
}

fn is_valid_name(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "!geder-list 1\n!name base-fr\n!version 7\n# banques\nbank.fr\n*.bank.fr\n\n";

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    #[test]
    fn sign_then_verify_roundtrip() {
        let k = key(1);
        let signed = sign(SAMPLE, &k).unwrap();
        let list = verify(signed.as_bytes(), &[k.verifying_key()]).unwrap();
        assert_eq!(list.name, "base-fr");
        assert_eq!(list.version, 7);
        assert_eq!(list.rules.len(), 2);
        // Re-signer remplace la signature au lieu d'en empiler une seconde.
        let resigned = sign(&signed, &k).unwrap();
        assert_eq!(resigned, signed);
    }

    #[test]
    fn rejects_unsigned_wrong_key_and_tampering() {
        let k = key(1);
        assert_eq!(verify(SAMPLE.as_bytes(), &[k.verifying_key()]), Err(ListError::MissingSignature));

        let signed = sign(SAMPLE, &k).unwrap();
        assert_eq!(verify(signed.as_bytes(), &[key(2).verifying_key()]), Err(ListError::BadSignature));

        let tampered = signed.replace("bank.fr\n", "evil.com\n");
        assert_eq!(verify(tampered.as_bytes(), &[k.verifying_key()]), Err(ListError::BadSignature));

        let appended = format!("{signed}evil.com\n");
        assert_eq!(verify(appended.as_bytes(), &[k.verifying_key()]), Err(ListError::TrailingData));
    }

    #[test]
    fn accepts_any_trusted_key_for_rotation() {
        let old = key(1);
        let new = key(2);
        let signed = sign(SAMPLE, &new).unwrap();
        assert!(verify(signed.as_bytes(), &[old.verifying_key(), new.verifying_key()]).is_ok());
    }

    #[test]
    fn reports_bad_lines() {
        assert_eq!(parse_unsigned("bank.fr\n"), Err(ListError::MissingMagic));
        assert_eq!(parse_unsigned("!geder-list 1\n!version 1\n"), Err(ListError::MissingName));
        assert_eq!(parse_unsigned("!geder-list 1\n!name a\n"), Err(ListError::MissingVersion));
        assert_eq!(
            parse_unsigned("!geder-list 1\n!name a\n!version 1\nbad domain\n"),
            Err(ListError::BadRule { line: 4, source: DomainError::BadChar })
        );
        assert_eq!(parse_unsigned("!geder-list 1\n!name a\n!expires 2027\n"), Err(ListError::BadDirective { line: 3 }));
        assert_eq!(parse_unsigned("!geder-list 1\n!name a\n!name b\n"), Err(ListError::BadDirective { line: 3 }));
    }

    #[test]
    fn signature_with_crlf_line_endings() {
        let k = key(3);
        let signed = sign(&SAMPLE.replace('\n', "\r\n"), &k).unwrap();
        assert!(verify(signed.as_bytes(), &[k.verifying_key()]).is_ok());
    }
}

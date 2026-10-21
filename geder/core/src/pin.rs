//! PIN administrateur (parent / mashgiach) : hachage Argon2id et anti-force-brute.
//!
//! Le PIN n'est jamais stocké en clair. Après quelques erreurs, chaque nouvel échec
//! double le délai d'attente. L'heure passée en paramètre doit venir de l'horloge
//! anti-triche de la plateforme (heure serveur + horloge monotone), pas de l'heure
//! système que l'utilisateur peut avancer.

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use rand_core::OsRng;

pub const MIN_LEN: usize = 6;
pub const MAX_LEN: usize = 12;
/// Essais libres avant le premier blocage.
pub const FREE_ATTEMPTS: u32 = 5;
const FIRST_LOCKOUT_SECS: u64 = 30;
const MAX_LOCKOUT_SECS: u64 = 24 * 3600;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PinError {
    #[error("le PIN doit contenir de {MIN_LEN} à {MAX_LEN} chiffres")]
    BadFormat,
    #[error("PIN trop simple (chiffres répétés ou suite)")]
    TooSimple,
    #[error("enregistrement de PIN illisible")]
    Corrupt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinCheck {
    Ok,
    Wrong { attempts_before_lockout: u32 },
    LockedOut { retry_in_secs: u64 },
}

/// État persistant du PIN (à stocker dans la base chiffrée de l'appareil).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinRecord {
    hash: String,
    failures: u32,
    locked_until: u64,
}

fn argon2() -> Argon2<'static> {
    // Recommandation OWASP : 19 Mio, 2 passes. Paramètres réduits en test pour la vitesse.
    let mem_kib = if cfg!(test) { 1024 } else { 19 * 1024 };
    let params = Params::new(mem_kib, 2, 1, None).expect("paramètres Argon2 valides");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

pub fn validate(pin: &str) -> Result<(), PinError> {
    if !(MIN_LEN..=MAX_LEN).contains(&pin.len()) || !pin.bytes().all(|b| b.is_ascii_digit()) {
        return Err(PinError::BadFormat);
    }
    let b = pin.as_bytes();
    let steps: Vec<i16> = b.windows(2).map(|w| i16::from(w[1]) - i16::from(w[0])).collect();
    if steps.iter().all(|&s| s == steps[0]) && steps[0].abs() <= 1 {
        return Err(PinError::TooSimple);
    }
    Ok(())
}

impl PinRecord {
    pub fn new(pin: &str) -> Result<Self, PinError> {
        validate(pin)?;
        let salt = SaltString::generate(&mut OsRng);
        let hash = argon2().hash_password(pin.as_bytes(), &salt).map_err(|_| PinError::Corrupt)?.to_string();
        Ok(PinRecord { hash, failures: 0, locked_until: 0 })
    }

    /// Vérifie un PIN. `now_secs` : heure de confiance en secondes Unix.
    pub fn verify(&mut self, pin: &str, now_secs: u64) -> PinCheck {
        if now_secs < self.locked_until {
            return PinCheck::LockedOut { retry_in_secs: self.locked_until - now_secs };
        }
        let ok = PasswordHash::new(&self.hash)
            .map(|h| argon2().verify_password(pin.as_bytes(), &h).is_ok())
            .unwrap_or(false);
        if ok {
            self.failures = 0;
            self.locked_until = 0;
            return PinCheck::Ok;
        }
        self.failures = self.failures.saturating_add(1);
        if self.failures < FREE_ATTEMPTS {
            return PinCheck::Wrong { attempts_before_lockout: FREE_ATTEMPTS - self.failures };
        }
        let exp = (self.failures - FREE_ATTEMPTS).min(20);
        let lockout = (FIRST_LOCKOUT_SECS << exp).min(MAX_LOCKOUT_SECS);
        self.locked_until = now_secs.saturating_add(lockout);
        PinCheck::LockedOut { retry_in_secs: lockout }
    }

    pub fn failures(&self) -> u32 {
        self.failures
    }

    /// Sérialise : `v1;<échecs>;<bloqué_jusqu'à>;<hash PHC>`.
    pub fn encode(&self) -> String {
        format!("v1;{};{};{}", self.failures, self.locked_until, self.hash)
    }

    pub fn decode(s: &str) -> Result<Self, PinError> {
        let mut parts = s.splitn(4, ';');
        if parts.next() != Some("v1") {
            return Err(PinError::Corrupt);
        }
        let failures = parts.next().and_then(|p| p.parse().ok()).ok_or(PinError::Corrupt)?;
        let locked_until = parts.next().and_then(|p| p.parse().ok()).ok_or(PinError::Corrupt)?;
        let hash = parts.next().ok_or(PinError::Corrupt)?;
        PasswordHash::new(hash).map_err(|_| PinError::Corrupt)?;
        Ok(PinRecord { hash: hash.to_owned(), failures, locked_until })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_format_and_simplicity() {
        assert_eq!(validate("12345"), Err(PinError::BadFormat));
        assert_eq!(validate("12345a"), Err(PinError::BadFormat));
        assert_eq!(validate("1234567890123"), Err(PinError::BadFormat));
        assert_eq!(validate("000000"), Err(PinError::TooSimple));
        assert_eq!(validate("123456"), Err(PinError::TooSimple));
        assert_eq!(validate("987654"), Err(PinError::TooSimple));
        assert_eq!(validate("135790"), Ok(()));
        assert_eq!(validate("481516"), Ok(()));
    }

    #[test]
    fn correct_pin_resets_failures() {
        let mut r = PinRecord::new("481516").unwrap();
        assert!(!r.encode().contains("481516"));
        assert_eq!(r.verify("000001", 100), PinCheck::Wrong { attempts_before_lockout: 4 });
        assert_eq!(r.verify("481516", 100), PinCheck::Ok);
        assert_eq!(r.failures(), 0);
    }

    #[test]
    fn lockout_doubles_and_blocks_even_correct_pin() {
        let mut r = PinRecord::new("481516").unwrap();
        let t = 1_000;
        for i in 1..FREE_ATTEMPTS {
            assert_eq!(r.verify("999990", t), PinCheck::Wrong { attempts_before_lockout: FREE_ATTEMPTS - i });
        }
        assert_eq!(r.verify("999990", t), PinCheck::LockedOut { retry_in_secs: 30 });
        // Pendant le blocage, même le bon PIN est refusé (pas d'oracle).
        assert_eq!(r.verify("481516", t + 10), PinCheck::LockedOut { retry_in_secs: 20 });
        assert_eq!(r.verify("999990", t + 30), PinCheck::LockedOut { retry_in_secs: 60 });
        assert_eq!(r.verify("481516", t + 90), PinCheck::Ok);
    }

    #[test]
    fn lockout_is_capped() {
        let mut r = PinRecord::new("481516").unwrap();
        r.failures = 100;
        assert_eq!(r.verify("999990", 0), PinCheck::LockedOut { retry_in_secs: MAX_LOCKOUT_SECS });
    }

    #[test]
    fn encode_decode_roundtrip() {
        let mut r = PinRecord::new("481516").unwrap();
        r.verify("999990", 5);
        let back = PinRecord::decode(&r.encode()).unwrap();
        assert_eq!(back, r);
        assert_eq!(PinRecord::decode("v1;0;0;pas-un-hash"), Err(PinError::Corrupt));
        assert_eq!(PinRecord::decode("v2;0;0;x"), Err(PinError::Corrupt));
    }
}

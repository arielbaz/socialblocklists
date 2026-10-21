//! Table de liaison DNS -> IP.
//!
//! Une IP n'est joignable que si notre propre résolveur vient de la renvoyer pour un
//! domaine autorisé. Le DoH, les IP codées en dur et les VPN tiers échouent donc
//! sans qu'on ait besoin de les connaître.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::domain::DomainName;

#[derive(Debug, Clone, Copy)]
pub struct BindingConfig {
    /// TTL minimal retenu, pour ne pas casser les sites qui annoncent un TTL de 0 à 5 s.
    pub min_ttl: Duration,
    /// TTL maximal retenu, pour qu'une IP réattribuée ne reste pas ouverte des jours.
    pub max_ttl: Duration,
    /// Marge ajoutée après expiration : les applis gardent souvent l'IP un peu plus longtemps.
    pub grace: Duration,
    /// Nombre maximal d'IP mémorisées.
    pub capacity: usize,
}

impl Default for BindingConfig {
    fn default() -> Self {
        Self {
            min_ttl: Duration::from_secs(60),
            max_ttl: Duration::from_secs(3600),
            grace: Duration::from_secs(300),
            capacity: 65_536,
        }
    }
}

#[derive(Debug, Clone)]
struct Entry {
    domain: DomainName,
    expires: Instant,
}

#[derive(Debug, Clone)]
pub struct BindingTable {
    config: BindingConfig,
    entries: HashMap<IpAddr, Entry>,
}

impl BindingTable {
    pub fn new(config: BindingConfig) -> Self {
        Self { config, entries: HashMap::new() }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn bind(&mut self, ip: IpAddr, domain: DomainName, ttl_secs: u32, now: Instant) {
        let ttl = Duration::from_secs(u64::from(ttl_secs)).clamp(self.config.min_ttl, self.config.max_ttl);
        let expires = now + ttl + self.config.grace;
        if let Some(e) = self.entries.get_mut(&ip) {
            // Une IP partagée par deux domaines autorisés garde l'échéance la plus lointaine.
            if expires >= e.expires {
                *e = Entry { domain, expires };
            }
            return;
        }
        if self.entries.len() >= self.config.capacity {
            self.purge(now);
        }
        if self.entries.len() >= self.config.capacity {
            if let Some(oldest) = self.entries.iter().min_by_key(|(_, e)| e.expires).map(|(ip, _)| *ip) {
                self.entries.remove(&oldest);
            }
        }
        self.entries.insert(ip, Entry { domain, expires });
    }

    /// Domaine autorisé auquel l'IP est liée, si la liaison est encore valide.
    pub fn lookup(&self, ip: &IpAddr, now: Instant) -> Option<&DomainName> {
        self.entries.get(ip).filter(|e| e.expires > now).map(|e| &e.domain)
    }

    pub fn purge(&mut self, now: Instant) {
        self.entries.retain(|_, e| e.expires > now);
    }

    /// Retire les liaisons des domaines qui ne sont plus autorisés (après mise à jour des listes).
    pub fn retain_domains(&mut self, mut allowed: impl FnMut(&DomainName) -> bool) {
        self.entries.retain(|_, e| allowed(&e.domain));
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(s: &str) -> DomainName {
        DomainName::parse(s).unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn binding_expires_after_ttl_and_grace() {
        let cfg = BindingConfig::default();
        let mut t = BindingTable::new(cfg);
        let t0 = Instant::now();
        t.bind(ip("1.2.3.4"), d("bank.fr"), 120, t0);
        assert_eq!(t.lookup(&ip("1.2.3.4"), t0).map(|d| d.as_str()), Some("bank.fr"));
        let edge = t0 + Duration::from_secs(120) + cfg.grace;
        assert!(t.lookup(&ip("1.2.3.4"), edge - Duration::from_secs(1)).is_some());
        assert!(t.lookup(&ip("1.2.3.4"), edge).is_none());
        assert!(t.lookup(&ip("5.6.7.8"), t0).is_none());
    }

    #[test]
    fn ttl_is_clamped() {
        let cfg = BindingConfig { grace: Duration::ZERO, ..Default::default() };
        let mut t = BindingTable::new(cfg);
        let t0 = Instant::now();
        t.bind(ip("1.1.1.1"), d("a.com"), 0, t0);
        t.bind(ip("2.2.2.2"), d("b.com"), u32::MAX, t0);
        assert!(t.lookup(&ip("1.1.1.1"), t0 + Duration::from_secs(59)).is_some());
        assert!(t.lookup(&ip("2.2.2.2"), t0 + Duration::from_secs(3600)).is_none());
    }

    #[test]
    fn rebinding_keeps_latest_expiry() {
        let mut t = BindingTable::new(BindingConfig::default());
        let t0 = Instant::now();
        t.bind(ip("1.1.1.1"), d("long.com"), 3000, t0);
        t.bind(ip("1.1.1.1"), d("short.com"), 60, t0);
        assert_eq!(t.lookup(&ip("1.1.1.1"), t0).unwrap().as_str(), "long.com");
    }

    #[test]
    fn capacity_evicts_soonest_expiring() {
        let cfg = BindingConfig { capacity: 2, ..Default::default() };
        let mut t = BindingTable::new(cfg);
        let t0 = Instant::now();
        t.bind(ip("1.1.1.1"), d("a.com"), 100, t0);
        t.bind(ip("2.2.2.2"), d("b.com"), 3000, t0);
        t.bind(ip("3.3.3.3"), d("c.com"), 3000, t0);
        assert_eq!(t.len(), 2);
        assert!(t.lookup(&ip("1.1.1.1"), t0).is_none());
        assert!(t.lookup(&ip("3.3.3.3"), t0).is_some());
    }
}

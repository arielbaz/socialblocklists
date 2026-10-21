//! Moteur de filtrage : refus par défaut, liste blanche, liaison DNS -> IP.
//!
//! Chaque plateforme (Android, Windows, Apple) n'écrit qu'un petit adaptateur :
//! elle lit les paquets de son interface TUN, appelle [`Engine::classify_packet`],
//! envoie les requêtes DNS autorisées au résolveur amont puis repasse la réponse
//! par [`Engine::handle_dns_response`] avant de la rendre à l'appli.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Instant;

use ed25519_dalek::VerifyingKey;

use crate::binding::{BindingConfig, BindingTable};
use crate::dns::{self, Message, RData};
use crate::domain::{DomainName, DomainSet};
use crate::list::{self, AllowList, ListError};
use crate::packet::{self, Packet, PacketError, Transport};
use crate::tls::{self, TlsError};

/// Règles intégrées au binaire, toujours actives : service GEDER et urgences.
const BUILTIN_LIST: &str = include_str!("../../lists/integre.txt");

#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// Adresse du résolveur virtuel annoncé aux applis (dans le sous-réseau TUN).
    pub resolver_v4: Ipv4Addr,
    pub resolver_v6: Option<Ipv6Addr>,
    pub bindings: BindingConfig,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            resolver_v4: Ipv4Addr::new(10, 111, 0, 53),
            resolver_v6: Some("fd00:6765:6465:72::53".parse().expect("adresse valide")),
            bindings: BindingConfig::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenyReason {
    /// QUIC / HTTP3 (UDP 443) : on force TCP, plus facile à contrôler.
    Quic,
    /// DNS chiffré sur le port 853.
    DnsOverTls,
    /// Requête DNS vers un autre résolveur que le nôtre.
    ForeignDns,
    /// IP qui n'a pas été renvoyée par notre résolveur pour un domaine autorisé.
    UnboundIp,
    /// Protocole autre que TCP / UDP.
    Protocol(u8),
    /// SNI TLS hors liste blanche (IP de CDN partagée).
    BlockedSni(String),
    /// TLS avec SNI chiffré : impossible de savoir quel site est demandé.
    EncryptedClientHello,
    Malformed,
    Fragment,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Allow { domain: DomainName },
    Deny(DenyReason),
}

impl Verdict {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Verdict::Allow { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacketVerdict<'a> {
    /// Requête DNS adressée à notre résolveur : charge utile UDP à passer à
    /// [`Engine::handle_dns_query`].
    DnsQuery(&'a [u8]),
    Allow {
        domain: DomainName,
    },
    Deny(DenyReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsAction {
    /// Domaine autorisé : envoyer la requête au résolveur amont (socket protégée),
    /// puis passer la réponse à [`Engine::handle_dns_response`].
    Forward,
    /// Répondre directement à l'appli avec ce paquet DNS.
    Reply {
        packet: Vec<u8>,
        /// Domaine refusé, pour proposer « demander l'ouverture » à l'utilisateur.
        blocked: Option<DomainName>,
    },
    /// Message illisible : l'ignorer.
    Drop,
}

/// Comme [`DnsAction`], mais au niveau des paquets IP lus sur la TUN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsPacketAction {
    /// Envoyer cette requête DNS (charge utile UDP) au résolveur amont par une socket
    /// protégée, puis appeler [`Engine::complete_dns_packet`] avec la réponse.
    Forward(Vec<u8>),
    /// Écrire ce paquet IP sur la TUN.
    Reply {
        packet: Vec<u8>,
        blocked: Option<DomainName>,
    },
    Drop,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EngineError {
    #[error(transparent)]
    List(#[from] ListError),
    #[error("liste « {name} » version {offered} plus ancienne que la version chargée {current}")]
    Rollback { name: String, current: u64, offered: u64 },
    #[error("réponse DNS invalide : {0}")]
    Dns(#[from] dns::DnsError),
    #[error("réponse DNS sans rapport avec la requête")]
    DnsMismatch,
    #[error("paquet invalide : {0}")]
    Packet(#[from] PacketError),
}

pub struct Engine {
    config: EngineConfig,
    trusted_keys: Vec<VerifyingKey>,
    builtin: AllowList,
    lists: BTreeMap<String, AllowList>,
    allow: DomainSet,
    bindings: BindingTable,
}

impl Engine {
    /// Crée un moteur sans liste chargée : seules les règles intégrées sont autorisées
    /// (mode « fail-closed »).
    pub fn new(config: EngineConfig, trusted_keys: Vec<VerifyingKey>) -> Self {
        let builtin = list::parse_unsigned(BUILTIN_LIST).expect("liste intégrée valide");
        let bindings = BindingTable::new(config.bindings);
        let mut engine =
            Engine { config, trusted_keys, builtin, lists: BTreeMap::new(), allow: DomainSet::new(), bindings };
        engine.rebuild();
        engine
    }

    pub fn config(&self) -> &EngineConfig {
        &self.config
    }

    /// Listes chargées : (nom, version).
    pub fn lists(&self) -> impl Iterator<Item = (&str, u64)> {
        self.lists.values().map(|l| (l.name.as_str(), l.version))
    }

    /// Vérifie et charge une liste signée. Une version inférieure à celle déjà
    /// chargée sous le même nom est refusée (anti-retour en arrière).
    pub fn load_list(&mut self, data: &[u8]) -> Result<&AllowList, EngineError> {
        let new = list::verify(data, &self.trusted_keys)?;
        if let Some(current) = self.lists.get(&new.name) {
            if new.version < current.version {
                return Err(EngineError::Rollback { name: new.name, current: current.version, offered: new.version });
            }
        }
        let name = new.name.clone();
        self.lists.insert(name.clone(), new);
        self.rebuild();
        Ok(&self.lists[&name])
    }

    pub fn unload_list(&mut self, name: &str) -> bool {
        let removed = self.lists.remove(name).is_some();
        if removed {
            self.rebuild();
        }
        removed
    }

    fn rebuild(&mut self) {
        let rules = self.builtin.rules.iter().chain(self.lists.values().flat_map(|l| l.rules.iter()));
        self.allow = rules.collect();
        let allow = &self.allow;
        self.bindings.retain_domains(|d| allow.contains(d));
    }

    pub fn is_domain_allowed(&self, name: &str) -> bool {
        DomainName::parse(name).is_ok_and(|d| self.allow.contains(&d))
    }

    fn is_resolver(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => v4 == self.config.resolver_v4,
            IpAddr::V6(v6) => Some(v6) == self.config.resolver_v6,
        }
    }

    /// Décide du sort d'une requête DNS envoyée à notre résolveur.
    pub fn handle_dns_query(&self, query: &[u8]) -> DnsAction {
        let msg = match Message::parse(query) {
            Ok(m) => m,
            Err(_) => return DnsAction::Drop,
        };
        let reply = |rcode, blocked| match dns::reply_empty(query, rcode) {
            Ok(packet) => DnsAction::Reply { packet, blocked },
            Err(_) => DnsAction::Drop,
        };
        if msg.is_response() {
            return DnsAction::Drop;
        }
        if msg.opcode() != 0 || msg.questions.len() != 1 || msg.questions[0].qclass != dns::CLASS_IN {
            return reply(dns::RCODE_REFUSED, None);
        }
        let q = &msg.questions[0];
        let name = match DomainName::parse(&q.name) {
            Ok(n) => n,
            Err(_) => return reply(dns::RCODE_NXDOMAIN, None),
        };
        if !self.allow.contains(&name) {
            return reply(dns::RCODE_NXDOMAIN, Some(name));
        }
        match q.qtype {
            dns::TYPE_A | dns::TYPE_AAAA | dns::TYPE_CNAME => DnsAction::Forward,
            // Les enregistrements HTTPS/SVCB transportent les clés ECH et des IP
            // « indices » qui contourneraient la liaison : on répond « pas de données ».
            _ => reply(dns::RCODE_NOERROR, None),
        }
    }

    /// Enregistre les IP d'une réponse amont pour un domaine autorisé.
    /// Seules les adresses de la chaîne CNAME partant du nom demandé sont liées.
    /// Renvoie le nombre d'IP liées.
    pub fn handle_dns_response(&mut self, response: &[u8], now: Instant) -> Result<usize, EngineError> {
        let msg = Message::parse(response)?;
        if !msg.is_response() || msg.rcode() != dns::RCODE_NOERROR || msg.questions.len() != 1 {
            return Ok(0);
        }
        let Ok(qname) = DomainName::parse(&msg.questions[0].name) else {
            return Ok(0);
        };
        if !self.allow.contains(&qname) {
            return Ok(0);
        }

        let mut chain = vec![qname.as_str().to_owned()];
        let in_chain = |chain: &[String], n: &str| chain.iter().any(|c| c.eq_ignore_ascii_case(n));
        // Les CNAME peuvent arriver dans le désordre : on boucle jusqu'à stabilité.
        loop {
            let before = chain.len();
            for rec in &msg.answers {
                if let RData::Cname(target) = &rec.data {
                    if in_chain(&chain, &rec.name) && !in_chain(&chain, target) {
                        chain.push(target.clone());
                    }
                }
            }
            if chain.len() == before {
                break;
            }
        }

        let mut bound = 0;
        for rec in &msg.answers {
            let ip = match rec.data {
                RData::A(v4) => IpAddr::V4(v4),
                RData::Aaaa(v6) => IpAddr::V6(v6),
                _ => continue,
            };
            if in_chain(&chain, &rec.name) {
                self.bindings.bind(ip, qname.clone(), rec.ttl, now);
                bound += 1;
            }
        }
        Ok(bound)
    }

    /// Décide si une nouvelle connexion sortante est autorisée.
    pub fn check_connection(&self, transport: Transport, dst: SocketAddr, now: Instant) -> Verdict {
        let port = dst.port();
        match transport {
            Transport::Other(p) => return Verdict::Deny(DenyReason::Protocol(p)),
            Transport::Udp if port == 443 => return Verdict::Deny(DenyReason::Quic),
            _ if port == 853 => return Verdict::Deny(DenyReason::DnsOverTls),
            _ if port == 53 => return Verdict::Deny(DenyReason::ForeignDns),
            _ => {}
        }
        match self.bindings.lookup(&dst.ip(), now) {
            Some(domain) => Verdict::Allow { domain: domain.clone() },
            None => Verdict::Deny(DenyReason::UnboundIp),
        }
    }

    /// Contrôle le début d'un flux TCP (ClientHello). `None` : données insuffisantes,
    /// rappeler avec la suite du flux.
    pub fn check_tls(&self, stream_start: &[u8]) -> Option<Result<(), DenyReason>> {
        match tls::parse_client_hello(stream_start) {
            Ok(ch) if ch.ech => Some(Err(DenyReason::EncryptedClientHello)),
            Ok(ch) => match ch.sni {
                Some(sni) if !self.is_domain_allowed(&sni) => Some(Err(DenyReason::BlockedSni(sni))),
                _ => Some(Ok(())),
            },
            Err(TlsError::Incomplete) => None,
            // Pas du TLS, ou TLS illisible : l'IP liée suffit.
            Err(TlsError::NotClientHello | TlsError::Malformed) => Some(Ok(())),
        }
    }

    /// Classe un paquet IP sortant lu sur l'interface TUN.
    ///
    /// Le contrôle du SNI fait ici est « au mieux » : un ClientHello réparti sur
    /// plusieurs segments est laissé passer. Le relais TCP doit appeler
    /// [`Engine::check_tls`] sur le flux réassemblé.
    pub fn classify_packet<'a>(&self, buf: &'a [u8], now: Instant) -> PacketVerdict<'a> {
        let pkt = match Packet::parse(buf) {
            Ok(p) => p,
            Err(PacketError::Fragment) => return PacketVerdict::Deny(DenyReason::Fragment),
            Err(_) => return PacketVerdict::Deny(DenyReason::Malformed),
        };
        if self.is_resolver(pkt.dst.ip()) {
            return match (pkt.transport, pkt.dst.port()) {
                (Transport::Udp, 53) => PacketVerdict::DnsQuery(pkt.payload),
                _ => PacketVerdict::Deny(DenyReason::ForeignDns),
            };
        }
        match self.check_connection(pkt.transport, pkt.dst, now) {
            Verdict::Allow { domain } => {
                if pkt.transport == Transport::Tcp && pkt.dst.port() == 443 && !pkt.payload.is_empty() {
                    if let Some(Err(reason)) = self.check_tls(pkt.payload) {
                        return PacketVerdict::Deny(reason);
                    }
                }
                PacketVerdict::Allow { domain }
            }
            Verdict::Deny(reason) => PacketVerdict::Deny(reason),
        }
    }

    /// Traite un paquet IP contenant une requête DNS pour notre résolveur.
    pub fn handle_dns_packet(&self, ip_packet: &[u8]) -> DnsPacketAction {
        let Ok(pkt) = Packet::parse(ip_packet) else { return DnsPacketAction::Drop };
        if pkt.transport != Transport::Udp || pkt.dst.port() != 53 || !self.is_resolver(pkt.dst.ip()) {
            return DnsPacketAction::Drop;
        }
        match self.handle_dns_query(pkt.payload) {
            DnsAction::Forward => DnsPacketAction::Forward(pkt.payload.to_vec()),
            DnsAction::Reply { packet, blocked } => match packet::build_udp_reply(&pkt, &packet) {
                Ok(packet) => DnsPacketAction::Reply { packet, blocked },
                Err(_) => DnsPacketAction::Drop,
            },
            DnsAction::Drop => DnsPacketAction::Drop,
        }
    }

    /// Enregistre la réponse amont à une requête transmise par [`Engine::handle_dns_packet`]
    /// et renvoie le paquet IP à écrire sur la TUN.
    pub fn complete_dns_packet(
        &mut self,
        ip_packet: &[u8],
        response: &[u8],
        now: Instant,
    ) -> Result<Vec<u8>, EngineError> {
        let pkt = Packet::parse(ip_packet)?;
        let query = Message::parse(pkt.payload)?;
        let reply = Message::parse(response)?;
        if !reply.is_response() || reply.id != query.id || reply.questions != query.questions {
            return Err(EngineError::DnsMismatch);
        }
        self.handle_dns_response(response, now)?;
        Ok(packet::build_udp_reply(&pkt, response)?)
    }

    /// Supprime les liaisons expirées (à appeler périodiquement).
    pub fn purge(&mut self, now: Instant) {
        self.bindings.purge(now);
    }

    pub fn binding_count(&self) -> usize {
        self.bindings.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::testutil::{query, response, Ans};
    use crate::packet::testutil::{ipv4, tcp, udp};
    use crate::packet::{PROTO_ICMP, PROTO_TCP, PROTO_UDP};
    use ed25519_dalek::SigningKey;
    use std::time::Duration;

    const LIST: &str = "!geder-list 1\n!name test\n!version 3\nbank.fr\nwww.bank.fr\n*.torah.org\n";

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[42; 32])
    }

    fn engine() -> Engine {
        let mut e = Engine::new(EngineConfig::default(), vec![key().verifying_key()]);
        e.load_list(list::sign(LIST, &key()).unwrap().as_bytes()).unwrap();
        e
    }

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn fail_closed_without_lists() {
        let e = Engine::new(EngineConfig::default(), vec![key().verifying_key()]);
        assert!(!e.is_domain_allowed("www.bank.fr"));
        assert!(!e.is_domain_allowed("google.com"));
        assert!(e.lists().next().is_none());
    }

    #[test]
    fn blocked_domain_gets_nxdomain_with_request_hint() {
        let e = engine();
        let q = query(1, "www.casino.com", dns::TYPE_A);
        match e.handle_dns_query(&q) {
            DnsAction::Reply { packet, blocked } => {
                assert_eq!(Message::parse(&packet).unwrap().rcode(), dns::RCODE_NXDOMAIN);
                assert_eq!(blocked.unwrap().as_str(), "www.casino.com");
            }
            other => panic!("attendu Reply, obtenu {other:?}"),
        }
    }

    #[test]
    fn allowed_domain_is_forwarded_and_https_records_suppressed() {
        let e = engine();
        assert_eq!(e.handle_dns_query(&query(1, "WWW.Bank.fr", dns::TYPE_A)), DnsAction::Forward);
        assert_eq!(e.handle_dns_query(&query(2, "shiur.torah.org", dns::TYPE_AAAA)), DnsAction::Forward);
        match e.handle_dns_query(&query(3, "www.bank.fr", dns::TYPE_HTTPS)) {
            DnsAction::Reply { packet, blocked: None } => {
                let m = Message::parse(&packet).unwrap();
                assert_eq!(m.rcode(), dns::RCODE_NOERROR);
                assert!(m.answers.is_empty());
            }
            other => panic!("attendu Reply vide, obtenu {other:?}"),
        }
        assert_eq!(e.handle_dns_query(b"\x00\x01"), DnsAction::Drop);
    }

    #[test]
    fn dns_to_ip_binding_end_to_end() {
        let mut e = engine();
        let t0 = Instant::now();
        let target = sa("93.184.216.34:443");

        // Avant résolution : IP inconnue, refusée.
        assert_eq!(e.check_connection(Transport::Tcp, target, t0), Verdict::Deny(DenyReason::UnboundIp));

        let q = query(5, "www.bank.fr", dns::TYPE_A);
        let r = response(
            &q,
            &[
                Ans::Cname("www.bank.fr", "bank.edge.cdn.net", 300),
                Ans::A("bank.edge.cdn.net", [93, 184, 216, 34], 120),
                // Enregistrement parasite hors de la chaîne CNAME : ignoré.
                Ans::A("evil.example", [6, 6, 6, 6], 120),
            ],
        );
        assert_eq!(e.handle_dns_response(&r, t0).unwrap(), 1);

        assert_eq!(
            e.check_connection(Transport::Tcp, target, t0),
            Verdict::Allow { domain: DomainName::parse("www.bank.fr").unwrap() }
        );
        assert!(!e.check_connection(Transport::Tcp, sa("6.6.6.6:443"), t0).is_allowed());
        // QUIC refusé même vers une IP liée.
        assert_eq!(e.check_connection(Transport::Udp, target, t0), Verdict::Deny(DenyReason::Quic));
        // Expiration.
        let later = t0 + Duration::from_secs(120 + 300);
        assert!(!e.check_connection(Transport::Tcp, target, later).is_allowed());
    }

    #[test]
    fn responses_for_blocked_names_bind_nothing() {
        let mut e = engine();
        let q = query(5, "doh.evil.net", dns::TYPE_A);
        let r = response(&q, &[Ans::A("doh.evil.net", [9, 9, 9, 9], 300)]);
        assert_eq!(e.handle_dns_response(&r, Instant::now()).unwrap(), 0);
        assert_eq!(e.binding_count(), 0);
    }

    #[test]
    fn bypass_attempts_are_denied() {
        let e = engine();
        let now = Instant::now();
        // DoH vers une IP codée en dur (pas de résolution préalable).
        assert_eq!(e.check_connection(Transport::Tcp, sa("1.1.1.1:443"), now), Verdict::Deny(DenyReason::UnboundIp));
        // DoT.
        assert_eq!(e.check_connection(Transport::Tcp, sa("1.1.1.1:853"), now), Verdict::Deny(DenyReason::DnsOverTls));
        // Résolveur tiers.
        assert_eq!(e.check_connection(Transport::Udp, sa("8.8.8.8:53"), now), Verdict::Deny(DenyReason::ForeignDns));
        // ICMP (tunnels ICMP).
        assert_eq!(
            e.check_connection(Transport::Other(PROTO_ICMP), sa("8.8.8.8:0"), now),
            Verdict::Deny(DenyReason::Protocol(PROTO_ICMP))
        );
    }

    #[test]
    fn classify_packets_from_tun() {
        let mut e = engine();
        let now = Instant::now();
        let dns_q = query(9, "www.bank.fr", dns::TYPE_A);

        let p = ipv4(PROTO_UDP, [10, 111, 0, 2], [10, 111, 0, 53], &udp(4000, 53, &dns_q));
        assert_eq!(e.classify_packet(&p, now), PacketVerdict::DnsQuery(&dns_q[..]));

        let p = ipv4(PROTO_TCP, [10, 111, 0, 2], [10, 111, 0, 53], &tcp(4000, 53, b""));
        assert_eq!(e.classify_packet(&p, now), PacketVerdict::Deny(DenyReason::ForeignDns));

        let r = response(&dns_q, &[Ans::A("www.bank.fr", [5, 5, 5, 5], 600)]);
        e.handle_dns_response(&r, now).unwrap();

        let syn = ipv4(PROTO_TCP, [10, 111, 0, 2], [5, 5, 5, 5], &tcp(4001, 443, b""));
        assert!(matches!(e.classify_packet(&syn, now), PacketVerdict::Allow { .. }));

        // Même IP (CDN partagé), mais SNI d'un site interdit.
        let ch = crate::tls::testutil::client_hello(Some("casino.com"), false);
        let p = ipv4(PROTO_TCP, [10, 111, 0, 2], [5, 5, 5, 5], &tcp(4001, 443, &ch));
        assert_eq!(e.classify_packet(&p, now), PacketVerdict::Deny(DenyReason::BlockedSni("casino.com".into())));

        let ch = crate::tls::testutil::client_hello(Some("www.bank.fr"), false);
        let p = ipv4(PROTO_TCP, [10, 111, 0, 2], [5, 5, 5, 5], &tcp(4001, 443, &ch));
        assert!(matches!(e.classify_packet(&p, now), PacketVerdict::Allow { .. }));

        let ch = crate::tls::testutil::client_hello(Some("www.bank.fr"), true);
        let p = ipv4(PROTO_TCP, [10, 111, 0, 2], [5, 5, 5, 5], &tcp(4001, 443, &ch));
        assert_eq!(e.classify_packet(&p, now), PacketVerdict::Deny(DenyReason::EncryptedClientHello));

        assert_eq!(e.classify_packet(&[0x45, 0, 0], now), PacketVerdict::Deny(DenyReason::Malformed));
    }

    #[test]
    fn rollback_is_refused_and_removed_domains_lose_bindings() {
        let mut e = engine();
        let now = Instant::now();
        let q = query(1, "bank.fr", dns::TYPE_A);
        e.handle_dns_response(&response(&q, &[Ans::A("bank.fr", [7, 7, 7, 7], 600)]), now).unwrap();
        assert!(e.check_connection(Transport::Tcp, sa("7.7.7.7:443"), now).is_allowed());

        let old = LIST.replace("!version 3", "!version 2");
        let err = e.load_list(list::sign(&old, &key()).unwrap().as_bytes()).unwrap_err();
        assert_eq!(err, EngineError::Rollback { name: "test".into(), current: 3, offered: 2 });

        let newer = "!geder-list 1\n!name test\n!version 4\n*.torah.org\n";
        e.load_list(list::sign(newer, &key()).unwrap().as_bytes()).unwrap();
        assert!(!e.is_domain_allowed("bank.fr"));
        assert!(!e.check_connection(Transport::Tcp, sa("7.7.7.7:443"), now).is_allowed());
    }

    #[test]
    fn dns_over_tun_packets() {
        let mut e = engine();
        let now = Instant::now();
        let client = [10, 111, 0, 1];
        let resolver = [10, 111, 0, 53];

        // Domaine bloqué : réponse NXDOMAIN déjà emballée en IP/UDP.
        let q = query(1, "casino.com", dns::TYPE_A);
        let p = ipv4(PROTO_UDP, client, resolver, &udp(4000, 53, &q));
        match e.handle_dns_packet(&p) {
            DnsPacketAction::Reply { packet, blocked } => {
                assert_eq!(blocked.unwrap().as_str(), "casino.com");
                let reply = Packet::parse(&packet).unwrap();
                assert_eq!(reply.dst, "10.111.0.1:4000".parse().unwrap());
                assert_eq!(Message::parse(reply.payload).unwrap().rcode(), dns::RCODE_NXDOMAIN);
            }
            other => panic!("attendu Reply, obtenu {other:?}"),
        }

        // Domaine autorisé : transmis, puis la réponse lie l'IP.
        let q = query(2, "www.bank.fr", dns::TYPE_A);
        let p = ipv4(PROTO_UDP, client, resolver, &udp(4001, 53, &q));
        assert_eq!(e.handle_dns_packet(&p), DnsPacketAction::Forward(q.clone()));
        let r = response(&q, &[Ans::A("www.bank.fr", [5, 4, 3, 2], 300)]);
        let out = e.complete_dns_packet(&p, &r, now).unwrap();
        let out = Packet::parse(&out).unwrap();
        assert_eq!(out.src, "10.111.0.53:53".parse().unwrap());
        assert_eq!(out.payload, &r[..]);
        assert!(e.check_connection(Transport::Tcp, sa("5.4.3.2:443"), now).is_allowed());

        // Réponse qui ne correspond pas à la requête : refusée, rien n'est lié.
        let other = response(&query(3, "www.bank.fr", dns::TYPE_A), &[Ans::A("www.bank.fr", [9, 9, 9, 9], 300)]);
        assert_eq!(e.complete_dns_packet(&p, &other, now), Err(EngineError::DnsMismatch));
        assert!(!e.check_connection(Transport::Tcp, sa("9.9.9.9:443"), now).is_allowed());

        // Paquet DNS adressé à un autre serveur : ignoré.
        let p = ipv4(PROTO_UDP, client, [8, 8, 8, 8], &udp(4002, 53, &q));
        assert_eq!(e.handle_dns_packet(&p), DnsPacketAction::Drop);
    }

    #[test]
    fn unsigned_list_is_refused() {
        let mut e = Engine::new(EngineConfig::default(), vec![key().verifying_key()]);
        assert_eq!(e.load_list(LIST.as_bytes()).unwrap_err(), EngineError::List(ListError::MissingSignature));
        assert!(!e.is_domain_allowed("bank.fr"));
    }

    #[test]
    fn builtin_list_is_valid_and_always_active() {
        let e = Engine::new(EngineConfig::default(), vec![]);
        assert!(!e.builtin.rules.is_empty());
        let first = e.builtin.rules[0].domain.as_str().to_owned();
        assert!(e.is_domain_allowed(&first));
    }
}

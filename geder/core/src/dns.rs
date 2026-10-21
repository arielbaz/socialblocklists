//! Lecture et construction minimales de messages DNS (RFC 1035).
//!
//! Le moteur n'a besoin que de la question d'une requête et des enregistrements
//! A / AAAA / CNAME d'une réponse. Tout est borné : pas de récursion, nombre de
//! sauts de compression limité, aucune lecture hors du tampon.

use std::net::{Ipv4Addr, Ipv6Addr};

pub const TYPE_A: u16 = 1;
pub const TYPE_CNAME: u16 = 5;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_SVCB: u16 = 64;
pub const TYPE_HTTPS: u16 = 65;
pub const CLASS_IN: u16 = 1;

pub const RCODE_NOERROR: u8 = 0;
pub const RCODE_SERVFAIL: u8 = 2;
pub const RCODE_NXDOMAIN: u8 = 3;
pub const RCODE_REFUSED: u8 = 5;

const HEADER_LEN: usize = 12;
const MAX_POINTER_JUMPS: usize = 16;
const MAX_RECORDS: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DnsError {
    #[error("message DNS tronqué")]
    Truncated,
    #[error("nom DNS invalide")]
    BadName,
    #[error("message DNS non pris en charge")]
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    /// Nom tel qu'il apparaît dans le message, labels séparés par des points.
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(String),
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub name: String,
    pub rtype: u16,
    pub ttl: u32,
    pub data: RData,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub id: u16,
    pub flags: u16,
    pub questions: Vec<Question>,
    pub answers: Vec<Record>,
    /// Position de la fin de la section question.
    question_end: usize,
}

impl Message {
    pub fn is_response(&self) -> bool {
        self.flags & 0x8000 != 0
    }

    pub fn opcode(&self) -> u8 {
        ((self.flags >> 11) & 0x0f) as u8
    }

    pub fn rcode(&self) -> u8 {
        (self.flags & 0x000f) as u8
    }

    /// Analyse l'en-tête, les questions et les réponses. Les sections autorité et
    /// additionnelle sont ignorées.
    pub fn parse(buf: &[u8]) -> Result<Self, DnsError> {
        if buf.len() < HEADER_LEN {
            return Err(DnsError::Truncated);
        }
        let id = read_u16(buf, 0)?;
        let flags = read_u16(buf, 2)?;
        let qdcount = read_u16(buf, 4)? as usize;
        let ancount = read_u16(buf, 6)? as usize;
        if qdcount > MAX_RECORDS || ancount > MAX_RECORDS {
            return Err(DnsError::Unsupported);
        }

        let mut pos = HEADER_LEN;
        let mut questions = Vec::with_capacity(qdcount);
        for _ in 0..qdcount {
            let (name, next) = read_name(buf, pos)?;
            let qtype = read_u16(buf, next)?;
            let qclass = read_u16(buf, next + 2)?;
            pos = next + 4;
            questions.push(Question { name, qtype, qclass });
        }
        let question_end = pos;

        let mut answers = Vec::with_capacity(ancount);
        for _ in 0..ancount {
            let (name, next) = read_name(buf, pos)?;
            let rtype = read_u16(buf, next)?;
            let ttl = read_u32(buf, next + 4)?;
            let rdlen = read_u16(buf, next + 8)? as usize;
            let rdata_start = next + 10;
            let rdata = buf.get(rdata_start..rdata_start + rdlen).ok_or(DnsError::Truncated)?;
            let data = match (rtype, rdlen) {
                (TYPE_A, 4) => RData::A(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3])),
                (TYPE_AAAA, 16) => {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(rdata);
                    RData::Aaaa(Ipv6Addr::from(octets))
                }
                (TYPE_A | TYPE_AAAA, _) => return Err(DnsError::Unsupported),
                (TYPE_CNAME, _) => RData::Cname(read_name(buf, rdata_start)?.0),
                _ => RData::Other,
            };
            pos = rdata_start + rdlen;
            answers.push(Record { name, rtype, ttl, data });
        }

        Ok(Message { id, flags, questions, answers, question_end })
    }
}

/// Construit une réponse sans enregistrement à une requête, avec le code donné
/// (`RCODE_NXDOMAIN` pour un domaine bloqué, `RCODE_NOERROR` pour « pas de données »).
/// La section question de la requête est recopiée telle quelle.
pub fn reply_empty(query: &[u8], rcode: u8) -> Result<Vec<u8>, DnsError> {
    let msg = Message::parse(query)?;
    if msg.is_response() || msg.questions.len() != 1 {
        return Err(DnsError::Unsupported);
    }
    const QR: u16 = 0x8000;
    const OPCODE_MASK: u16 = 0x7800;
    const RD: u16 = 0x0100;
    const RA: u16 = 0x0080;
    let flags = QR | (msg.flags & (OPCODE_MASK | RD)) | RA | u16::from(rcode & 0x0f);

    let mut out = Vec::with_capacity(msg.question_end);
    out.extend_from_slice(&msg.id.to_be_bytes());
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    out.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // an, ns, ar
    out.extend_from_slice(&query[HEADER_LEN..msg.question_end]);
    Ok(out)
}

fn read_u16(buf: &[u8], pos: usize) -> Result<u16, DnsError> {
    buf.get(pos..pos + 2).map(|b| u16::from_be_bytes([b[0], b[1]])).ok_or(DnsError::Truncated)
}

fn read_u32(buf: &[u8], pos: usize) -> Result<u32, DnsError> {
    buf.get(pos..pos + 4).map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]])).ok_or(DnsError::Truncated)
}

/// Lit un nom (avec compression) et renvoie la position qui suit le nom dans le flux.
fn read_name(buf: &[u8], start: usize) -> Result<(String, usize), DnsError> {
    let mut name = String::new();
    let mut pos = start;
    let mut end_after: Option<usize> = None;
    let mut jumps = 0;
    loop {
        let len = *buf.get(pos).ok_or(DnsError::Truncated)? as usize;
        match len & 0xc0 {
            0x00 => {
                if len == 0 {
                    let end = end_after.unwrap_or(pos + 1);
                    return Ok((name, end));
                }
                let label = buf.get(pos + 1..pos + 1 + len).ok_or(DnsError::Truncated)?;
                if !label.iter().all(|b| b.is_ascii_graphic() && *b != b'.') {
                    return Err(DnsError::BadName);
                }
                if !name.is_empty() {
                    name.push('.');
                }
                name.extend(label.iter().map(|&b| b as char));
                if name.len() > crate::domain::MAX_NAME_LEN {
                    return Err(DnsError::BadName);
                }
                pos += 1 + len;
            }
            0xc0 => {
                let low = *buf.get(pos + 1).ok_or(DnsError::Truncated)? as usize;
                jumps += 1;
                if jumps > MAX_POINTER_JUMPS {
                    return Err(DnsError::BadName);
                }
                end_after.get_or_insert(pos + 2);
                pos = ((len & 0x3f) << 8) | low;
            }
            _ => return Err(DnsError::BadName),
        }
    }
}

#[cfg(test)]
pub(crate) mod testutil {
    //! Construction de messages pour les tests.
    use super::*;

    pub fn encode_name(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for label in name.split('.').filter(|l| !l.is_empty()) {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out
    }

    pub fn query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
        out.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
        out.extend_from_slice(&encode_name(name));
        out.extend_from_slice(&qtype.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out
    }

    pub enum Ans<'a> {
        A(&'a str, [u8; 4], u32),
        Aaaa(&'a str, Ipv6Addr, u32),
        Cname(&'a str, &'a str, u32),
    }

    /// Réponse NOERROR à `query` ; le nom de chaque réponse est écrit en clair,
    /// sauf s'il est égal à la question, auquel cas un pointeur de compression est utilisé.
    pub fn response(query: &[u8], answers: &[Ans]) -> Vec<u8> {
        let q = Message::parse(query).unwrap();
        let qname = q.questions[0].name.clone();
        let mut out = query.to_vec();
        out[2] |= 0x80; // QR
        out[3] |= 0x80; // RA
        out[6..8].copy_from_slice(&(answers.len() as u16).to_be_bytes());
        let write_name = |out: &mut Vec<u8>, n: &str| {
            if n == qname {
                out.extend_from_slice(&[0xc0, 0x0c]);
            } else {
                out.extend_from_slice(&encode_name(n));
            }
        };
        for a in answers {
            let (n, rtype, ttl, rdata) = match a {
                Ans::A(n, ip, ttl) => (*n, TYPE_A, *ttl, ip.to_vec()),
                Ans::Aaaa(n, ip, ttl) => (*n, TYPE_AAAA, *ttl, ip.octets().to_vec()),
                Ans::Cname(n, target, ttl) => (*n, TYPE_CNAME, *ttl, encode_name(target)),
            };
            write_name(&mut out, n);
            out.extend_from_slice(&rtype.to_be_bytes());
            out.extend_from_slice(&CLASS_IN.to_be_bytes());
            out.extend_from_slice(&ttl.to_be_bytes());
            out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            out.extend_from_slice(&rdata);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::*;
    use super::*;

    #[test]
    fn parses_query() {
        let q = query(0x1234, "www.Example.com", TYPE_A);
        let m = Message::parse(&q).unwrap();
        assert_eq!(m.id, 0x1234);
        assert!(!m.is_response());
        assert_eq!(m.questions, vec![Question { name: "www.Example.com".into(), qtype: TYPE_A, qclass: CLASS_IN }]);
    }

    #[test]
    fn parses_response_with_compression_and_cname() {
        let q = query(7, "www.bank.fr", TYPE_A);
        let r = response(
            &q,
            &[
                Ans::Cname("www.bank.fr", "bank.edge.cdn.net", 300),
                Ans::A("bank.edge.cdn.net", [93, 184, 216, 34], 60),
                Ans::Aaaa("bank.edge.cdn.net", "2001:db8::1".parse().unwrap(), 60),
            ],
        );
        let m = Message::parse(&r).unwrap();
        assert!(m.is_response());
        assert_eq!(m.answers.len(), 3);
        assert_eq!(m.answers[0].name, "www.bank.fr");
        assert_eq!(m.answers[0].data, RData::Cname("bank.edge.cdn.net".into()));
        assert_eq!(m.answers[1].data, RData::A(Ipv4Addr::new(93, 184, 216, 34)));
        assert_eq!(m.answers[1].ttl, 60);
        assert_eq!(m.answers[2].data, RData::Aaaa("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn rejects_pointer_loops_and_truncation() {
        let mut q = query(1, "a.b", TYPE_A);
        // Remplace le nom par un pointeur vers lui-même.
        q.truncate(HEADER_LEN);
        q.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]);
        assert_eq!(Message::parse(&q), Err(DnsError::BadName));

        let q = query(1, "example.com", TYPE_A);
        for cut in 0..q.len() {
            assert!(Message::parse(&q[..cut]).is_err(), "coupure à {cut}");
        }
    }

    #[test]
    fn rejects_bad_a_record_length() {
        let q = query(9, "x.org", TYPE_A);
        let mut r = response(&q, &[Ans::A("x.org", [1, 2, 3, 4], 60)]);
        let len = r.len();
        r[len - 6..len - 4].copy_from_slice(&3u16.to_be_bytes());
        r.pop();
        assert_eq!(Message::parse(&r), Err(DnsError::Unsupported));
    }

    #[test]
    fn builds_nxdomain_reply() {
        let q = query(0xbeef, "blocked.example", TYPE_AAAA);
        let r = reply_empty(&q, RCODE_NXDOMAIN).unwrap();
        let m = Message::parse(&r).unwrap();
        assert_eq!(m.id, 0xbeef);
        assert!(m.is_response());
        assert_eq!(m.rcode(), RCODE_NXDOMAIN);
        assert_eq!(m.questions[0].name, "blocked.example");
        assert_eq!(m.questions[0].qtype, TYPE_AAAA);
        assert!(m.answers.is_empty());
    }

    #[test]
    fn garbage_never_panics() {
        // Petit fuzz déterministe : aucune entrée ne doit provoquer de panique.
        let mut seed: u32 = 0x1234_5678;
        for _ in 0..20_000 {
            let len = (seed % 80) as usize;
            let buf: Vec<u8> = (0..len)
                .map(|_| {
                    seed ^= seed << 13;
                    seed ^= seed >> 17;
                    seed ^= seed << 5;
                    seed as u8
                })
                .collect();
            let _ = Message::parse(&buf);
            let _ = reply_empty(&buf, RCODE_NXDOMAIN);
        }
    }
}

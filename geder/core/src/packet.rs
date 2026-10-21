//! Lecture des en-têtes IPv4 / IPv6 / TCP / UDP des paquets sortants lus sur
//! l'interface TUN (VpnService Android, Wintun, Network Extension).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;
pub const PROTO_ICMPV6: u8 = 58;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Tcp,
    Udp,
    /// Autre protocole IP (ICMP, GRE, ESP...), avec son numéro.
    Other(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PacketError {
    #[error("paquet IP tronqué ou mal formé")]
    Malformed,
    #[error("fragment IP sans en-tête de transport")]
    Fragment,
    #[error("version IP inconnue")]
    UnknownVersion,
}

/// Vue sur un paquet IP sortant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Packet<'a> {
    pub transport: Transport,
    pub src: SocketAddr,
    pub dst: SocketAddr,
    /// Charge utile de transport (après l'en-tête TCP/UDP). Vide pour `Other`.
    pub payload: &'a [u8],
}

impl<'a> Packet<'a> {
    pub fn parse(buf: &'a [u8]) -> Result<Self, PacketError> {
        match buf.first().map(|b| b >> 4) {
            Some(4) => parse_v4(buf),
            Some(6) => parse_v6(buf),
            Some(_) => Err(PacketError::UnknownVersion),
            None => Err(PacketError::Malformed),
        }
    }
}

fn parse_v4(buf: &[u8]) -> Result<Packet<'_>, PacketError> {
    if buf.len() < 20 {
        return Err(PacketError::Malformed);
    }
    let ihl = usize::from(buf[0] & 0x0f) * 4;
    let total = usize::from(u16::from_be_bytes([buf[2], buf[3]]));
    if ihl < 20 || total < ihl || total > buf.len() {
        return Err(PacketError::Malformed);
    }
    let frag_offset = u16::from_be_bytes([buf[6], buf[7]]) & 0x1fff;
    if frag_offset != 0 {
        return Err(PacketError::Fragment);
    }
    let proto = buf[9];
    let src = IpAddr::V4(Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]));
    let dst = IpAddr::V4(Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]));
    transport(proto, src, dst, &buf[ihl..total])
}

fn parse_v6(buf: &[u8]) -> Result<Packet<'_>, PacketError> {
    if buf.len() < 40 {
        return Err(PacketError::Malformed);
    }
    let payload_len = usize::from(u16::from_be_bytes([buf[4], buf[5]]));
    let end = 40 + payload_len;
    if end > buf.len() {
        return Err(PacketError::Malformed);
    }
    let mut octets = [0u8; 16];
    octets.copy_from_slice(&buf[8..24]);
    let src = IpAddr::V6(Ipv6Addr::from(octets));
    octets.copy_from_slice(&buf[24..40]);
    let dst = IpAddr::V6(Ipv6Addr::from(octets));

    // Parcourt les en-têtes d'extension courants. Un fragment est refusé : on ne
    // peut pas juger un paquet dont on ne voit pas le port de destination.
    let mut next = buf[6];
    let mut pos = 40;
    loop {
        match next {
            0 | 43 | 60 => {
                let hdr = buf.get(pos..pos + 2).ok_or(PacketError::Malformed)?;
                next = hdr[0];
                pos += (usize::from(hdr[1]) + 1) * 8;
                if pos > end {
                    return Err(PacketError::Malformed);
                }
            }
            44 => return Err(PacketError::Fragment),
            _ => break,
        }
    }
    transport(next, src, dst, &buf[pos..end])
}

fn transport<'a>(proto: u8, src: IpAddr, dst: IpAddr, seg: &'a [u8]) -> Result<Packet<'a>, PacketError> {
    let ports = |seg: &[u8]| (u16::from_be_bytes([seg[0], seg[1]]), u16::from_be_bytes([seg[2], seg[3]]));
    match proto {
        PROTO_TCP => {
            if seg.len() < 20 {
                return Err(PacketError::Malformed);
            }
            let data_off = usize::from(seg[12] >> 4) * 4;
            if data_off < 20 || data_off > seg.len() {
                return Err(PacketError::Malformed);
            }
            let (sp, dp) = ports(seg);
            Ok(Packet {
                transport: Transport::Tcp,
                src: SocketAddr::new(src, sp),
                dst: SocketAddr::new(dst, dp),
                payload: &seg[data_off..],
            })
        }
        PROTO_UDP => {
            if seg.len() < 8 {
                return Err(PacketError::Malformed);
            }
            let udp_len = usize::from(u16::from_be_bytes([seg[4], seg[5]]));
            if udp_len < 8 || udp_len > seg.len() {
                return Err(PacketError::Malformed);
            }
            let (sp, dp) = ports(seg);
            Ok(Packet {
                transport: Transport::Udp,
                src: SocketAddr::new(src, sp),
                dst: SocketAddr::new(dst, dp),
                payload: &seg[8..udp_len],
            })
        }
        other => Ok(Packet {
            transport: Transport::Other(other),
            src: SocketAddr::new(src, 0),
            dst: SocketAddr::new(dst, 0),
            payload: &[],
        }),
    }
}

/// Construit la réponse UDP à un paquet reçu sur la TUN : adresses et ports
/// inversés, sommes de contrôle IPv4 et UDP calculées.
pub fn build_udp_reply(request: &Packet, payload: &[u8]) -> Result<Vec<u8>, PacketError> {
    if request.transport != Transport::Udp {
        return Err(PacketError::Malformed);
    }
    let (src, dst) = (request.dst, request.src);
    let udp_len = 8 + payload.len();
    let udp_len16 = u16::try_from(udp_len).map_err(|_| PacketError::Malformed)?;

    let mut udp = Vec::with_capacity(udp_len);
    udp.extend_from_slice(&src.port().to_be_bytes());
    udp.extend_from_slice(&dst.port().to_be_bytes());
    udp.extend_from_slice(&udp_len16.to_be_bytes());
    udp.extend_from_slice(&[0, 0]);
    udp.extend_from_slice(payload);

    let mut out = match (src.ip(), dst.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let total = u16::try_from(20 + udp_len).map_err(|_| PacketError::Malformed)?;
            let mut h = vec![0x45, 0];
            h.extend_from_slice(&total.to_be_bytes());
            h.extend_from_slice(&[0, 0, 0x40, 0, 64, PROTO_UDP, 0, 0]);
            h.extend_from_slice(&s.octets());
            h.extend_from_slice(&d.octets());
            let csum = checksum(&[&h]);
            h[10..12].copy_from_slice(&csum.to_be_bytes());
            let pseudo = [&s.octets()[..], &d.octets()[..], &[0, PROTO_UDP], &udp_len16.to_be_bytes()].concat();
            set_udp_checksum(&mut udp, &pseudo);
            h
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let mut h = vec![0x60, 0, 0, 0];
            h.extend_from_slice(&udp_len16.to_be_bytes());
            h.extend_from_slice(&[PROTO_UDP, 64]);
            h.extend_from_slice(&s.octets());
            h.extend_from_slice(&d.octets());
            let pseudo =
                [&s.octets()[..], &d.octets()[..], &(udp_len as u32).to_be_bytes(), &[0, 0, 0, PROTO_UDP]].concat();
            set_udp_checksum(&mut udp, &pseudo);
            h
        }
        _ => return Err(PacketError::Malformed),
    };
    out.extend_from_slice(&udp);
    Ok(out)
}

fn set_udp_checksum(udp: &mut [u8], pseudo: &[u8]) {
    let csum = match checksum(&[pseudo, udp]) {
        0 => 0xffff, // 0 signifie « pas de somme » en UDP
        c => c,
    };
    udp[6..8].copy_from_slice(&csum.to_be_bytes());
}

/// Somme de contrôle Internet (RFC 1071) sur des morceaux concaténés de longueur paire,
/// sauf éventuellement le dernier.
fn checksum(parts: &[&[u8]]) -> u16 {
    let mut sum: u32 = 0;
    for part in parts {
        let mut chunks = part.chunks_exact(2);
        for c in &mut chunks {
            sum += u32::from(u16::from_be_bytes([c[0], c[1]]));
        }
        if let [last] = chunks.remainder() {
            sum += u32::from(*last) << 8;
        }
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
pub(crate) mod testutil {
    use super::*;

    /// Paquet IPv4 minimal (sans somme de contrôle : le moteur ne la vérifie pas).
    pub fn ipv4(proto: u8, src: [u8; 4], dst: [u8; 4], l4: &[u8]) -> Vec<u8> {
        let total = (20 + l4.len()) as u16;
        let mut p = vec![0x45, 0];
        p.extend_from_slice(&total.to_be_bytes());
        p.extend_from_slice(&[0, 0, 0x40, 0, 64, proto, 0, 0]);
        p.extend_from_slice(&src);
        p.extend_from_slice(&dst);
        p.extend_from_slice(l4);
        p
    }

    pub fn ipv6(next: u8, src: Ipv6Addr, dst: Ipv6Addr, l4: &[u8]) -> Vec<u8> {
        let mut p = vec![0x60, 0, 0, 0];
        p.extend_from_slice(&(l4.len() as u16).to_be_bytes());
        p.extend_from_slice(&[next, 64]);
        p.extend_from_slice(&src.octets());
        p.extend_from_slice(&dst.octets());
        p.extend_from_slice(l4);
        p
    }

    pub fn udp(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let mut s = Vec::new();
        s.extend_from_slice(&sport.to_be_bytes());
        s.extend_from_slice(&dport.to_be_bytes());
        s.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        s.extend_from_slice(&[0, 0]);
        s.extend_from_slice(payload);
        s
    }

    pub fn tcp(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let mut s = Vec::new();
        s.extend_from_slice(&sport.to_be_bytes());
        s.extend_from_slice(&dport.to_be_bytes());
        s.extend_from_slice(&[0; 8]); // seq, ack
        s.extend_from_slice(&[0x50, 0x02, 0xff, 0xff, 0, 0, 0, 0]); // offset 5, SYN
        s.extend_from_slice(payload);
        s
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::*;
    use super::*;

    #[test]
    fn parses_ipv4_udp() {
        let p = ipv4(PROTO_UDP, [10, 0, 0, 2], [10, 111, 0, 53], &udp(40000, 53, b"hello"));
        let pkt = Packet::parse(&p).unwrap();
        assert_eq!(pkt.transport, Transport::Udp);
        assert_eq!(pkt.dst, "10.111.0.53:53".parse().unwrap());
        assert_eq!(pkt.src.port(), 40000);
        assert_eq!(pkt.payload, b"hello");
    }

    #[test]
    fn parses_ipv4_tcp() {
        let p = ipv4(PROTO_TCP, [10, 0, 0, 2], [1, 2, 3, 4], &tcp(5555, 443, b"data"));
        let pkt = Packet::parse(&p).unwrap();
        assert_eq!(pkt.transport, Transport::Tcp);
        assert_eq!(pkt.dst, "1.2.3.4:443".parse().unwrap());
        assert_eq!(pkt.payload, b"data");
    }

    #[test]
    fn parses_ipv6_with_extension_header() {
        let src: Ipv6Addr = "fd00::2".parse().unwrap();
        let dst: Ipv6Addr = "2001:db8::5".parse().unwrap();
        let mut l4 = vec![PROTO_TCP, 0, 0, 0, 0, 0, 0, 0]; // hop-by-hop, 8 octets
        l4.extend_from_slice(&tcp(1, 443, b""));
        let p = ipv6(0, src, dst, &l4);
        let pkt = Packet::parse(&p).unwrap();
        assert_eq!(pkt.transport, Transport::Tcp);
        assert_eq!(pkt.dst, SocketAddr::new(dst.into(), 443));
    }

    #[test]
    fn rejects_fragments() {
        let mut p = ipv4(PROTO_UDP, [10, 0, 0, 2], [1, 1, 1, 1], &udp(1, 53, b""));
        p[6] = 0x00;
        p[7] = 0x10; // offset non nul
        assert_eq!(Packet::parse(&p), Err(PacketError::Fragment));

        let src: Ipv6Addr = "fd00::2".parse().unwrap();
        let p = ipv6(44, src, src, &[PROTO_UDP, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(Packet::parse(&p), Err(PacketError::Fragment));
    }

    #[test]
    fn rejects_truncated_packets() {
        let p = ipv4(PROTO_TCP, [10, 0, 0, 2], [1, 2, 3, 4], &tcp(5555, 443, b"data"));
        for cut in 0..p.len() - 4 {
            assert!(Packet::parse(&p[..cut]).is_err(), "coupure à {cut}");
        }
    }

    #[test]
    fn other_protocols_are_reported() {
        let p = ipv4(PROTO_ICMP, [10, 0, 0, 2], [8, 8, 8, 8], &[8, 0, 0, 0]);
        assert_eq!(Packet::parse(&p).unwrap().transport, Transport::Other(PROTO_ICMP));
    }

    #[test]
    fn checksum_matches_rfc1071_example() {
        // Exemple de la RFC 1071, section 3 : somme 0xddf2, complément 0x220d.
        assert_eq!(checksum(&[&[0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7]]), 0x220d);
    }

    #[test]
    fn udp_reply_ipv4_has_valid_checksums() {
        let req = ipv4(PROTO_UDP, [10, 111, 0, 1], [10, 111, 0, 53], &udp(40000, 53, b"q"));
        let reply = build_udp_reply(&Packet::parse(&req).unwrap(), b"odd-length").unwrap();
        let pkt = Packet::parse(&reply).unwrap();
        assert_eq!(pkt.src, "10.111.0.53:53".parse().unwrap());
        assert_eq!(pkt.dst, "10.111.0.1:40000".parse().unwrap());
        assert_eq!(pkt.payload, b"odd-length");
        assert_eq!(checksum(&[&reply[..20]]), 0);
        let udp_len = (reply.len() - 20) as u16;
        let pseudo = [&reply[12..20], &[0, PROTO_UDP], &udp_len.to_be_bytes()[..]].concat();
        assert_eq!(checksum(&[&pseudo, &reply[20..]]), 0);
    }

    #[test]
    fn udp_reply_ipv6_has_valid_checksum() {
        let a: Ipv6Addr = "fd00::1".parse().unwrap();
        let r: Ipv6Addr = "fd00::53".parse().unwrap();
        let req = ipv6(PROTO_UDP, a, r, &udp(5000, 53, b"q"));
        let reply = build_udp_reply(&Packet::parse(&req).unwrap(), b"answer").unwrap();
        let pkt = Packet::parse(&reply).unwrap();
        assert_eq!(pkt.dst, SocketAddr::new(a.into(), 5000));
        assert_eq!(pkt.payload, b"answer");
        let udp_len = (reply.len() - 40) as u32;
        let pseudo = [&reply[8..40], &udp_len.to_be_bytes()[..], &[0, 0, 0, PROTO_UDP]].concat();
        assert_eq!(checksum(&[&pseudo, &reply[40..]]), 0);
    }

    #[test]
    fn udp_reply_requires_udp() {
        let req = ipv4(PROTO_TCP, [10, 0, 0, 1], [1, 2, 3, 4], &tcp(1, 2, b""));
        assert_eq!(build_udp_reply(&Packet::parse(&req).unwrap(), b""), Err(PacketError::Malformed));
    }
}

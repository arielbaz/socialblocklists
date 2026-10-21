//! Lecture du nom de serveur (SNI) dans un TLS ClientHello, sans déchiffrement.
//!
//! Sert de seconde barrière après la liaison DNS -> IP : sur une IP de CDN partagée
//! entre un site autorisé et un site interdit, le SNI dit lequel est demandé.
//! Un ClientHello qui annonce l'ECH (SNI chiffré) doit être refusé par l'appelant.

const CONTENT_HANDSHAKE: u8 = 0x16;
const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello {
    pub sni: Option<String>,
    /// Le ClientHello porte une extension ECH : le vrai nom est chiffré.
    pub ech: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TlsError {
    #[error("pas un ClientHello TLS")]
    NotClientHello,
    #[error("ClientHello incomplet : attendre la suite du flux")]
    Incomplete,
    #[error("ClientHello mal formé")]
    Malformed,
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], TlsError> {
        let out = self.buf.get(self.pos..self.pos + n).ok_or(TlsError::Malformed)?;
        self.pos += n;
        Ok(out)
    }
    fn u8(&mut self) -> Result<u8, TlsError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, TlsError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    fn vec8(&mut self) -> Result<&'a [u8], TlsError> {
        let n = self.u8()? as usize;
        self.take(n)
    }
    fn vec16(&mut self) -> Result<&'a [u8], TlsError> {
        let n = self.u16()? as usize;
        self.take(n)
    }
}

/// Analyse le début d'un flux TCP client. Seul le premier enregistrement TLS est lu ;
/// un ClientHello réparti sur plusieurs enregistrements renvoie `Malformed`.
pub fn parse_client_hello(stream: &[u8]) -> Result<ClientHello, TlsError> {
    if stream.len() < 5 {
        return Err(if stream.is_empty() || stream[0] == CONTENT_HANDSHAKE {
            TlsError::Incomplete
        } else {
            TlsError::NotClientHello
        });
    }
    if stream[0] != CONTENT_HANDSHAKE || stream[1] != 0x03 {
        return Err(TlsError::NotClientHello);
    }
    let record_len = usize::from(u16::from_be_bytes([stream[3], stream[4]]));
    let record = match stream.get(5..5 + record_len) {
        Some(r) => r,
        None => return Err(TlsError::Incomplete),
    };

    let mut r = Reader { buf: record, pos: 0 };
    if r.u8()? != HANDSHAKE_CLIENT_HELLO {
        return Err(TlsError::NotClientHello);
    }
    let hs = r.take(3)?;
    let hs_len = (usize::from(hs[0]) << 16) | (usize::from(hs[1]) << 8) | usize::from(hs[2]);
    let body = r.take(hs_len)?;

    let mut r = Reader { buf: body, pos: 0 };
    r.take(2 + 32)?; // version + random
    r.vec8()?; // session id
    r.vec16()?; // cipher suites
    r.vec8()?; // compression methods
    if r.pos == body.len() {
        return Ok(ClientHello { sni: None, ech: false });
    }
    let mut exts = Reader { buf: r.vec16()?, pos: 0 };

    let mut out = ClientHello { sni: None, ech: false };
    while exts.pos < exts.buf.len() {
        let ty = exts.u16()?;
        let data = exts.vec16()?;
        match ty {
            EXT_SERVER_NAME => {
                let mut list = Reader { buf: data, pos: 0 };
                let mut names = Reader { buf: list.vec16()?, pos: 0 };
                while names.pos < names.buf.len() {
                    let kind = names.u8()?;
                    let name = names.vec16()?;
                    if kind == 0 {
                        let name = std::str::from_utf8(name).map_err(|_| TlsError::Malformed)?;
                        out.sni = Some(name.to_owned());
                    }
                }
            }
            EXT_ENCRYPTED_CLIENT_HELLO => out.ech = true,
            _ => {}
        }
    }
    Ok(out)
}

#[cfg(test)]
pub(crate) mod testutil {
    pub fn client_hello(sni: Option<&str>, ech: bool) -> Vec<u8> {
        let mut exts = Vec::new();
        if let Some(name) = sni {
            let mut entry = vec![0u8];
            entry.extend_from_slice(&(name.len() as u16).to_be_bytes());
            entry.extend_from_slice(name.as_bytes());
            let mut list = (entry.len() as u16).to_be_bytes().to_vec();
            list.extend_from_slice(&entry);
            exts.extend_from_slice(&0u16.to_be_bytes());
            exts.extend_from_slice(&(list.len() as u16).to_be_bytes());
            exts.extend_from_slice(&list);
        }
        if ech {
            exts.extend_from_slice(&[0xfe, 0x0d, 0, 2, 0xaa, 0xbb]);
        }
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[7u8; 32]);
        body.push(0); // session id
        body.extend_from_slice(&[0, 2, 0x13, 0x01]); // une suite
        body.extend_from_slice(&[1, 0]); // compression null
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut hs = vec![0x01];
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&body);

        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::client_hello;
    use super::*;

    #[test]
    fn extracts_sni() {
        let ch = parse_client_hello(&client_hello(Some("www.bank.fr"), false)).unwrap();
        assert_eq!(ch, ClientHello { sni: Some("www.bank.fr".into()), ech: false });
    }

    #[test]
    fn detects_ech() {
        let ch = parse_client_hello(&client_hello(Some("public.cdn.net"), true)).unwrap();
        assert!(ch.ech);
    }

    #[test]
    fn missing_sni() {
        let ch = parse_client_hello(&client_hello(None, false)).unwrap();
        assert_eq!(ch.sni, None);
    }

    #[test]
    fn incomplete_and_foreign_streams() {
        let full = client_hello(Some("example.com"), false);
        assert_eq!(parse_client_hello(&full[..3]), Err(TlsError::Incomplete));
        assert_eq!(parse_client_hello(&full[..full.len() - 1]), Err(TlsError::Incomplete));
        assert_eq!(parse_client_hello(b"GET / HTTP/1.1\r\n"), Err(TlsError::NotClientHello));
    }

    #[test]
    fn corrupted_lengths_never_panic() {
        let full = client_hello(Some("example.com"), true);
        for i in 5..full.len() {
            for v in [0x00, 0x7f, 0xff] {
                let mut b = full.clone();
                b[i] = v;
                let _ = parse_client_hello(&b);
            }
        }
    }
}

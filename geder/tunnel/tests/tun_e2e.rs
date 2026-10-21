//! Test de bout en bout sur une vraie interface TUN Linux.
//!
//! Il faut les droits root (CAP_NET_ADMIN) :
//! `sudo -E cargo test -p geder-tunnel --test tun_e2e -- --ignored`
//!
//! Le sous-réseau 10.200.0.0/24 est routé dans la TUN. Le « serveur » 10.200.0.80
//! n'existe pas vraiment : le dialer de test redirige ses connexions vers des serveurs
//! d'écho locaux, et le résolveur amont vers un faux DNS local.

use std::collections::HashSet;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::IntoRawFd;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use geder_core::dns::{self, Message, RData};
use geder_core::{list, DomainName, Engine, EngineConfig};
use geder_tunnel::{BoxFuture, Dialer, Events, RunningTunnel, TunnelConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::timeout;

const SERVER: Ipv4Addr = Ipv4Addr::new(10, 200, 0, 80);
const RESOLVER: Ipv4Addr = Ipv4Addr::new(10, 200, 0, 53);
const UPSTREAM: &str = "192.0.2.53:53";
const LIST: &str = "!geder-list 1\n!name e2e\n!version 1\nallowed.test\n";

struct TestDialer {
    echo_tcp: SocketAddr,
    echo_udp: SocketAddr,
    dns_udp: SocketAddr,
    dns_tcp: SocketAddr,
    dialed: Mutex<Vec<SocketAddr>>,
}

impl TestDialer {
    fn redirect(&self, dst: SocketAddr, tcp: bool) -> io::Result<SocketAddr> {
        self.dialed.lock().unwrap().push(dst);
        if dst == UPSTREAM.parse().unwrap() {
            Ok(if tcp { self.dns_tcp } else { self.dns_udp })
        } else if dst.ip() == SERVER {
            Ok(if tcp { self.echo_tcp } else { self.echo_udp })
        } else {
            Err(io::Error::other(format!("destination inattendue {dst}")))
        }
    }
}

impl Dialer for TestDialer {
    fn tcp(&self, dst: SocketAddr) -> BoxFuture<'_, io::Result<TcpStream>> {
        Box::pin(async move { TcpStream::connect(self.redirect(dst, true)?).await })
    }
    fn udp(&self, dst: SocketAddr) -> BoxFuture<'_, io::Result<UdpSocket>> {
        Box::pin(async move {
            let target = self.redirect(dst, false)?;
            let s = UdpSocket::bind("127.0.0.1:0").await?;
            s.connect(target).await?;
            Ok(s)
        })
    }
}

#[derive(Default)]
struct Recorder(Mutex<HashSet<String>>);
impl Events for Recorder {
    fn blocked_domain(&self, domain: &DomainName) {
        self.0.lock().unwrap().insert(domain.to_string());
    }
}

fn dns_query(id: u16, name: &str) -> Vec<u8> {
    let mut q = id.to_be_bytes().to_vec();
    q.extend_from_slice(&[1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.extend_from_slice(&[0, 0, 1, 0, 1]);
    q
}

/// Faux résolveur amont : `allowed.test` -> 10.200.0.80.
fn fake_answer(query: &[u8]) -> Vec<u8> {
    let mut r = query.to_vec();
    r[2] |= 0x80;
    r[3] |= 0x80;
    let name = Message::parse(query).unwrap().questions[0].name.to_ascii_lowercase();
    if name == "allowed.test" {
        r[7] = 1;
        r.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 1, 0x2c, 0, 4]);
        r.extend_from_slice(&SERVER.octets());
    } else {
        r[3] |= dns::RCODE_NXDOMAIN;
    }
    r
}

fn client_hello(sni: &str) -> Vec<u8> {
    let mut entry = vec![0u8];
    entry.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    entry.extend_from_slice(sni.as_bytes());
    let mut ext = vec![0, 0];
    ext.extend_from_slice(&((entry.len() + 2) as u16).to_be_bytes());
    ext.extend_from_slice(&(entry.len() as u16).to_be_bytes());
    ext.extend_from_slice(&entry);
    let mut body = vec![3, 3];
    body.extend_from_slice(&[9; 32]);
    body.extend_from_slice(&[0, 0, 2, 0x13, 1, 1, 0]);
    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext);
    let mut hs = vec![1];
    hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    hs.extend_from_slice(&body);
    let mut rec = vec![0x16, 3, 1];
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

async fn spawn_servers() -> (SocketAddr, SocketAddr, SocketAddr, SocketAddr) {
    let echo_tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_tcp_addr = echo_tcp.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = echo_tcp.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    let echo_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo_udp_addr = echo_udp.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            let (n, from) = echo_udp.recv_from(&mut buf).await.unwrap();
            echo_udp.send_to(&buf[..n], from).await.unwrap();
        }
    });
    let dns_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dns_udp_addr = dns_udp.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            let (n, from) = dns_udp.recv_from(&mut buf).await.unwrap();
            dns_udp.send_to(&fake_answer(&buf[..n]), from).await.unwrap();
        }
    });
    let dns_tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dns_tcp_addr = dns_tcp.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = dns_tcp.accept().await.unwrap();
            tokio::spawn(async move {
                let mut len = [0u8; 2];
                s.read_exact(&mut len).await.unwrap();
                let mut q = vec![0u8; u16::from_be_bytes(len) as usize];
                s.read_exact(&mut q).await.unwrap();
                let a = fake_answer(&q);
                s.write_all(&(a.len() as u16).to_be_bytes()).await.unwrap();
                s.write_all(&a).await.unwrap();
            });
        }
    });
    (echo_tcp_addr, echo_udp_addr, dns_udp_addr, dns_tcp_addr)
}

async fn ask_dns_udp(name: &str, id: u16) -> Message {
    let s = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    s.connect((RESOLVER, 53)).await.unwrap();
    s.send(&dns_query(id, name)).await.unwrap();
    let mut buf = [0u8; 2048];
    let n = timeout(Duration::from_secs(5), s.recv(&mut buf)).await.expect("réponse DNS").unwrap();
    Message::parse(&buf[..n]).unwrap()
}

/// Envoie `data` et renvoie ce qui revient avant la fermeture ou le délai.
async fn tcp_exchange(port: u16, data: &[u8]) -> Vec<u8> {
    let Ok(Ok(mut s)) = timeout(Duration::from_secs(3), TcpStream::connect((SERVER, port))).await else {
        return Vec::new();
    };
    if s.write_all(data).await.is_err() {
        return Vec::new();
    }
    let mut out = vec![0u8; data.len()];
    match timeout(Duration::from_secs(3), s.read_exact(&mut out)).await {
        Ok(Ok(_)) => out,
        _ => Vec::new(),
    }
}

async fn udp_exchange(port: u16, data: &[u8]) -> Option<Vec<u8>> {
    let s = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    s.connect((SERVER, port)).await.unwrap();
    s.send(data).await.unwrap();
    let mut buf = [0u8; 2048];
    match timeout(Duration::from_secs(2), s.recv(&mut buf)).await {
        Ok(Ok(n)) => Some(buf[..n].to_vec()),
        _ => None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "nécessite root (interface TUN)"]
async fn full_tunnel_end_to_end() {
    let (echo_tcp, echo_udp, dns_udp, dns_tcp) = spawn_servers().await;
    let dialer = Arc::new(TestDialer { echo_tcp, echo_udp, dns_udp, dns_tcp, dialed: Mutex::default() });
    let events = Arc::new(Recorder::default());

    let key = SigningKey::from_bytes(&[7; 32]);
    let config = EngineConfig { resolver_v4: RESOLVER, resolver_v6: None, ..Default::default() };
    let mut engine = Engine::new(config, vec![key.verifying_key()]);
    engine.load_list(list::sign(LIST, &key).unwrap().as_bytes()).unwrap();
    let engine = Arc::new(Mutex::new(engine));

    // Comme sur Android : la TUN est créée ailleurs et seul son descripteur est confié au tunnel.
    let mut tun_config = tun::Configuration::default();
    tun_config.tun_name("geder-e2e0").address((10, 200, 0, 1)).netmask((255, 255, 255, 0)).mtu(1500).up();
    let fd = tun::create(&tun_config).expect("création TUN (root requis)").into_raw_fd();

    let tunnel_config = TunnelConfig {
        upstream_dns: vec![UPSTREAM.parse().unwrap()],
        tls_peek_timeout: Duration::from_secs(2),
        ..Default::default()
    };
    let tunnel =
        RunningTunnel::spawn_from_fd(fd, engine, dialer.clone(), events.clone(), tunnel_config).expect("démarrage");

    // 1. IP non résolue par notre DNS : aucune connexion sortante.
    assert!(tcp_exchange(7, b"ping").await.is_empty(), "IP non liée relayée");
    assert!(dialer.dialed.lock().unwrap().is_empty());

    // 2. Domaine hors liste : NXDOMAIN, signalé à l'appli, jamais transmis en amont.
    let r = ask_dns_udp("blocked.test", 1).await;
    assert_eq!(r.rcode(), dns::RCODE_NXDOMAIN);
    assert!(events.0.lock().unwrap().contains("blocked.test"));
    assert!(dialer.dialed.lock().unwrap().is_empty());

    // 3. Domaine autorisé : résolu par l'amont.
    let r = ask_dns_udp("allowed.test", 2).await;
    assert_eq!(r.answers.iter().map(|a| a.data.clone()).collect::<Vec<_>>(), vec![RData::A(SERVER)]);

    // 4. L'IP est maintenant liée : connexion relayée.
    assert_eq!(tcp_exchange(7, b"bonjour").await, b"bonjour");

    // 5. Port 443 : SNI interdit refusé, SNI autorisé relayé.
    assert!(tcp_exchange(443, &client_hello("evil.test")).await.is_empty(), "SNI interdit relayé");
    let ch = client_hello("allowed.test");
    assert_eq!(tcp_exchange(443, &ch).await, ch);

    // 6. QUIC refusé, autre UDP vers l'IP liée relayé.
    assert_eq!(udp_exchange(443, b"quic").await, None);
    assert_eq!(udp_exchange(123, b"ntp").await, Some(b"ntp".to_vec()));

    // 7. DNS sur TCP vers notre résolveur.
    let mut s = TcpStream::connect((RESOLVER, 53)).await.unwrap();
    let q = dns_query(3, "allowed.test");
    s.write_all(&(q.len() as u16).to_be_bytes()).await.unwrap();
    s.write_all(&q).await.unwrap();
    let mut len = [0u8; 2];
    timeout(Duration::from_secs(5), s.read_exact(&mut len)).await.unwrap().unwrap();
    let mut a = vec![0u8; u16::from_be_bytes(len) as usize];
    s.read_exact(&mut a).await.unwrap();
    assert_eq!(Message::parse(&a).unwrap().answers.len(), 1);

    let stopped = tokio::task::spawn_blocking(move || tunnel.stop());
    timeout(Duration::from_secs(5), stopped).await.expect("arrêt du tunnel").unwrap().unwrap();
}

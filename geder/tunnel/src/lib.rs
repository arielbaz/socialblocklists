//! # geder-tunnel
//!
//! Tunnel complet : tout le trafic de l'appareil entre dans la TUN, une pile TCP/IP
//! en espace utilisateur (`ipstack`) termine chaque connexion, et le moteur décide
//! avant qu'une vraie connexion ne soit ouverte vers Internet.
//!
//! - DNS vers notre résolveur virtuel (UDP et TCP) : traité par le moteur, transmis
//!   au résolveur amont seulement pour un domaine autorisé.
//! - Nouvelle connexion TCP : refusée si l'IP n'est pas liée à un domaine autorisé ;
//!   sur le port 443, le ClientHello est lu et son SNI contrôlé avant de se connecter.
//! - Flux UDP : relayé seulement vers une IP liée, jamais vers le port 443 (QUIC).
//! - Tout autre protocole (ICMP...) : abandonné.
//!
//! La décision est prise une fois, à l'ouverture : une liaison qui expire pendant
//! une connexion ne la coupe pas.

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use geder_core::dns;
use geder_core::{DnsAction, DomainName, Engine, Transport, Verdict};
use ipstack::{IpStack, IpStackConfig, IpStackStream, IpStackTcpStream, IpStackUdpStream};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::oneshot;
use tokio::time::timeout;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Ouvre les vraies connexions vers Internet, hors du tunnel.
///
/// Sur Android, chaque socket doit être « protégée » (`VpnService.protect`) avant
/// de se connecter, sinon elle repartirait dans notre propre TUN : voir [`ProtectedDialer`].
pub trait Dialer: Send + Sync + 'static {
    fn tcp(&self, dst: SocketAddr) -> BoxFuture<'_, io::Result<TcpStream>>;
    /// Socket UDP connectée à `dst`.
    fn udp(&self, dst: SocketAddr) -> BoxFuture<'_, io::Result<UdpSocket>>;
}

/// Sort une socket du VPN (sur Android : `VpnService.protect(fd)`).
pub trait Protect: Send + Sync + 'static {
    fn protect(&self, fd: i32) -> bool;
}

/// [`Dialer`] qui protège chaque socket avant de se connecter.
pub struct ProtectedDialer<P>(pub P);

#[cfg(unix)]
impl<P: Protect> Dialer for ProtectedDialer<P> {
    fn tcp(&self, dst: SocketAddr) -> BoxFuture<'_, io::Result<TcpStream>> {
        Box::pin(async move {
            use std::os::fd::AsRawFd;
            let socket =
                if dst.is_ipv4() { tokio::net::TcpSocket::new_v4()? } else { tokio::net::TcpSocket::new_v6()? };
            if !self.0.protect(socket.as_raw_fd()) {
                return Err(io::Error::other("protection de la socket refusée"));
            }
            socket.connect(dst).await
        })
    }

    fn udp(&self, dst: SocketAddr) -> BoxFuture<'_, io::Result<UdpSocket>> {
        Box::pin(async move {
            use std::os::fd::AsRawFd;
            let any: SocketAddr = if dst.is_ipv4() { "0.0.0.0:0".parse().unwrap() } else { "[::]:0".parse().unwrap() };
            let socket = UdpSocket::bind(any).await?;
            if !self.0.protect(socket.as_raw_fd()) {
                return Err(io::Error::other("protection de la socket refusée"));
            }
            socket.connect(dst).await?;
            Ok(socket)
        })
    }
}

/// Événements remontés à l'application.
pub trait Events: Send + Sync + 'static {
    /// Un domaine a été refusé : base du bouton « demander l'ouverture ».
    fn blocked_domain(&self, _domain: &DomainName) {}
}

pub struct NoEvents;
impl Events for NoEvents {}

#[derive(Debug, Clone)]
pub struct TunnelConfig {
    pub mtu: u16,
    /// Résolveurs amont, essayés dans l'ordre.
    pub upstream_dns: Vec<SocketAddr>,
    pub dns_timeout: Duration,
    /// Délai maximal pour recevoir le ClientHello d'une connexion vers le port 443.
    pub tls_peek_timeout: Duration,
    /// Taille maximale lue pour trouver le ClientHello.
    pub tls_peek_max: usize,
    pub tcp_idle_timeout: Duration,
    pub udp_idle_timeout: Duration,
}

impl Default for TunnelConfig {
    fn default() -> Self {
        Self {
            mtu: 1500,
            // Cloudflare « Families » : filtre adulte et malveillant, en seconde couche.
            upstream_dns: vec![
                "1.1.1.3:53".parse().unwrap(),
                "1.0.0.3:53".parse().unwrap(),
                "[2606:4700:4700::1113]:53".parse().unwrap(),
            ],
            dns_timeout: Duration::from_secs(4),
            tls_peek_timeout: Duration::from_secs(10),
            tls_peek_max: 16 * 1024,
            tcp_idle_timeout: Duration::from_secs(600),
            udp_idle_timeout: Duration::from_secs(60),
        }
    }
}

struct Ctx {
    engine: Arc<Mutex<Engine>>,
    dialer: Arc<dyn Dialer>,
    events: Arc<dyn Events>,
    config: TunnelConfig,
    resolvers: Vec<IpAddr>,
}

impl Ctx {
    /// Accès au moteur. Un verrou empoisonné (panique ailleurs) ne doit pas ouvrir le
    /// filtre : on continue avec l'état existant, qui reste en refus par défaut.
    fn engine(&self) -> std::sync::MutexGuard<'_, Engine> {
        self.engine.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn is_resolver(&self, ip: IpAddr) -> bool {
        self.resolvers.contains(&ip)
    }
}

/// Fait tourner le tunnel jusqu'à `shutdown` (ou la fin du périphérique).
/// Doit être appelée dans un runtime tokio multi-thread.
pub async fn run<D>(
    device: D,
    engine: Arc<Mutex<Engine>>,
    dialer: Arc<dyn Dialer>,
    events: Arc<dyn Events>,
    config: TunnelConfig,
    mut shutdown: oneshot::Receiver<()>,
) -> io::Result<()>
where
    D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let resolvers = {
        let e = engine.lock().unwrap_or_else(|e| e.into_inner());
        let c = e.config();
        std::iter::once(IpAddr::V4(c.resolver_v4)).chain(c.resolver_v6.map(IpAddr::V6)).collect()
    };
    let mut stack_config = IpStackConfig::default();
    stack_config.mtu(config.mtu).map_err(io::Error::other)?;
    stack_config.udp_timeout(config.udp_idle_timeout);
    let mut tcp_config = ipstack::TcpConfig::default();
    tcp_config.timeout = config.tcp_idle_timeout;
    stack_config.with_tcp_config(tcp_config);

    let mut stack = IpStack::new(stack_config, device);
    let ctx = Arc::new(Ctx { engine, dialer, events, config, resolvers });
    let mut purge = tokio::time::interval(Duration::from_secs(60));

    loop {
        tokio::select! {
            _ = &mut shutdown => return Ok(()),
            _ = purge.tick() => ctx.engine().purge(Instant::now()),
            accepted = stack.accept() => {
                let stream = accepted.map_err(io::Error::other)?;
                let ctx = ctx.clone();
                match stream {
                    IpStackStream::Tcp(tcp) => { tokio::spawn(handle_tcp(ctx, tcp)); }
                    IpStackStream::Udp(udp) => { tokio::spawn(handle_udp(ctx, udp)); }
                    // ICMP, protocoles inconnus : refus par défaut (on ne répond rien).
                    IpStackStream::UnknownTransport(_) | IpStackStream::UnknownNetwork(_) => {}
                }
            }
        }
    }
}

async fn handle_tcp(ctx: Arc<Ctx>, mut app: IpStackTcpStream) {
    let dst = app.peer_addr();
    if ctx.is_resolver(dst.ip()) {
        if dst.port() == 53 {
            serve_dns_tcp(&ctx, &mut app).await;
        }
        return;
    }
    let verdict = ctx.engine().check_connection(Transport::Tcp, dst, Instant::now());
    let Verdict::Allow { domain } = verdict else {
        log::debug!("TCP {dst} refusé : {verdict:?}");
        return;
    };

    // Sur 443, le client parle en premier : on lit le ClientHello avant de se connecter.
    let mut head = Vec::new();
    if dst.port() == 443 {
        match peek_client_hello(&ctx, &mut app, &mut head).await {
            Ok(()) => {}
            Err(reason) => {
                log::info!("TCP {dst} ({domain}) refusé : {reason}");
                return;
            }
        }
    }

    let mut upstream = match ctx.dialer.tcp(dst).await {
        Ok(s) => s,
        Err(e) => {
            log::debug!("TCP {dst} injoignable : {e}");
            return;
        }
    };
    if !head.is_empty() && upstream.write_all(&head).await.is_err() {
        return;
    }
    let _ = tokio::io::copy_bidirectional(&mut app, &mut upstream).await;
    let _ = upstream.shutdown().await;
    let _ = app.shutdown().await;
}

/// Lit le début du flux jusqu'à pouvoir juger le ClientHello.
async fn peek_client_hello(ctx: &Ctx, app: &mut IpStackTcpStream, head: &mut Vec<u8>) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + ctx.config.tls_peek_timeout;
    let mut buf = vec![0u8; 4096];
    loop {
        if !head.is_empty() {
            match ctx.engine().check_tls(head) {
                Some(Ok(())) => return Ok(()),
                Some(Err(reason)) => return Err(format!("{reason:?}")),
                None => {}
            }
        }
        if head.len() >= ctx.config.tls_peek_max {
            return Err("ClientHello trop long".into());
        }
        let n = match tokio::time::timeout_at(deadline, app.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) => return Err("flux fermé avant le ClientHello".into()),
            Ok(Ok(n)) => n,
            Err(_) => return Err("ClientHello non reçu à temps".into()),
        };
        head.extend_from_slice(&buf[..n]);
    }
}

async fn handle_udp(ctx: Arc<Ctx>, mut app: IpStackUdpStream) {
    let dst = app.peer_addr();
    if ctx.is_resolver(dst.ip()) {
        if dst.port() == 53 {
            serve_dns_udp(&ctx, &mut app).await;
        }
        return;
    }
    let verdict = ctx.engine().check_connection(Transport::Udp, dst, Instant::now());
    if !verdict.is_allowed() {
        log::debug!("UDP {dst} refusé : {verdict:?}");
        return;
    }
    let Ok(upstream) = ctx.dialer.udp(dst).await else { return };
    let mut from_app = vec![0u8; 65535];
    let mut from_net = vec![0u8; 65535];
    loop {
        tokio::select! {
            r = app.read(&mut from_app) => match r {
                Ok(n) if n > 0 => { if upstream.send(&from_app[..n]).await.is_err() { return } }
                _ => return, // fin ou délai d'inactivité de la pile
            },
            r = timeout(ctx.config.udp_idle_timeout, upstream.recv(&mut from_net)) => match r {
                Ok(Ok(n)) => { if app.write_all(&from_net[..n]).await.is_err() { return } }
                _ => return,
            },
        }
    }
}

async fn serve_dns_udp(ctx: &Ctx, app: &mut IpStackUdpStream) {
    let mut buf = vec![0u8; 4096];
    loop {
        let n = match app.read(&mut buf).await {
            Ok(n) if n > 0 => n,
            _ => return,
        };
        if let Some(reply) = resolve(ctx, &buf[..n], false).await {
            if app.write_all(&reply).await.is_err() {
                return;
            }
        }
    }
}

/// DNS sur TCP (RFC 7766) : chaque message est précédé de sa longueur sur 2 octets.
async fn serve_dns_tcp(ctx: &Ctx, app: &mut IpStackTcpStream) {
    loop {
        let mut len = [0u8; 2];
        if app.read_exact(&mut len).await.is_err() {
            return;
        }
        let mut query = vec![0u8; usize::from(u16::from_be_bytes(len))];
        if app.read_exact(&mut query).await.is_err() {
            return;
        }
        let Some(reply) = resolve(ctx, &query, true).await else { continue };
        let Ok(reply_len) = u16::try_from(reply.len()) else { continue };
        if app.write_all(&reply_len.to_be_bytes()).await.is_err() || app.write_all(&reply).await.is_err() {
            return;
        }
    }
}

/// Réponse DNS à rendre à l'appli, ou `None` pour ignorer la requête.
async fn resolve(ctx: &Ctx, query: &[u8], over_tcp: bool) -> Option<Vec<u8>> {
    let action = ctx.engine().handle_dns_query(query);
    match action {
        DnsAction::Drop => None,
        DnsAction::Reply { packet, blocked } => {
            if let Some(domain) = blocked {
                log::info!("domaine refusé : {domain}");
                ctx.events.blocked_domain(&domain);
            }
            Some(packet)
        }
        DnsAction::Forward => {
            for server in &ctx.config.upstream_dns {
                let answer = if over_tcp {
                    query_upstream_tcp(ctx, *server, query).await
                } else {
                    query_upstream_udp(ctx, *server, query).await
                };
                let Ok(response) = answer else { continue };
                // Réponse sans rapport avec la requête : jamais rendue, rien n'est lié.
                if ctx.engine().accept_dns_response(query, &response, Instant::now()).is_ok() {
                    return Some(response);
                }
            }
            dns::reply_empty(query, dns::RCODE_SERVFAIL).ok()
        }
    }
}

async fn query_upstream_udp(ctx: &Ctx, server: SocketAddr, query: &[u8]) -> io::Result<Vec<u8>> {
    let socket = ctx.dialer.udp(server).await?;
    socket.send(query).await?;
    let mut buf = vec![0u8; 4096];
    let n = timeout(ctx.config.dns_timeout, socket.recv(&mut buf)).await.map_err(|_| io::ErrorKind::TimedOut)??;
    buf.truncate(n);
    Ok(buf)
}

async fn query_upstream_tcp(ctx: &Ctx, server: SocketAddr, query: &[u8]) -> io::Result<Vec<u8>> {
    let exchange = async {
        let mut s = ctx.dialer.tcp(server).await?;
        let len = u16::try_from(query.len()).map_err(|_| io::ErrorKind::InvalidInput)?;
        s.write_all(&len.to_be_bytes()).await?;
        s.write_all(query).await?;
        let mut len = [0u8; 2];
        s.read_exact(&mut len).await?;
        let mut buf = vec![0u8; usize::from(u16::from_be_bytes(len))];
        s.read_exact(&mut buf).await?;
        Ok(buf)
    };
    timeout(ctx.config.dns_timeout, exchange).await.map_err(|_| io::ErrorKind::TimedOut)?
}

/// Tunnel lancé dans son propre thread et son propre runtime, à partir du
/// descripteur de la TUN (sur Android : `ParcelFileDescriptor.detachFd()`).
/// Le tunnel devient propriétaire du descripteur et le ferme à l'arrêt.
#[cfg(unix)]
pub struct RunningTunnel {
    stop: Option<oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<io::Result<()>>>,
}

#[cfg(unix)]
impl RunningTunnel {
    pub fn spawn_from_fd(
        fd: i32,
        engine: Arc<Mutex<Engine>>,
        dialer: Arc<dyn Dialer>,
        events: Arc<dyn Events>,
        config: TunnelConfig,
    ) -> io::Result<Self> {
        let (stop, stop_rx) = oneshot::channel();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<io::Result<()>>();
        let thread = std::thread::Builder::new().name("geder-tunnel".into()).spawn(move || {
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_name("geder-net")
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = ready_tx.send(Err(e));
                    return Ok(());
                }
            };
            let result = rt.block_on(async move {
                let mut tun_config = tun::Configuration::default();
                tun_config.raw_fd(fd).mtu(config.mtu);
                let device = match tun::create_as_async(&tun_config) {
                    Ok(d) => d,
                    Err(e) => {
                        let _ = ready_tx.send(Err(io::Error::other(e)));
                        return Ok(());
                    }
                };
                let _ = ready_tx.send(Ok(()));
                run(device, engine, dialer, events, config, stop_rx).await
            });
            rt.shutdown_timeout(Duration::from_secs(2));
            result
        })?;
        match ready_rx.recv() {
            Ok(Ok(())) => Ok(RunningTunnel { stop: Some(stop), thread: Some(thread) }),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(io::Error::other("le thread du tunnel s'est arrêté au démarrage")),
        }
    }

    /// Arrête le tunnel et attend la fin de son thread (la TUN est alors fermée).
    pub fn stop(mut self) -> io::Result<()> {
        self.shutdown()
    }

    fn shutdown(&mut self) -> io::Result<()> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        match self.thread.take().map(|t| t.join()) {
            Some(Ok(result)) => result,
            Some(Err(_)) => Err(io::Error::other("le thread du tunnel a paniqué")),
            None => Ok(()),
        }
    }
}

#[cfg(unix)]
impl Drop for RunningTunnel {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

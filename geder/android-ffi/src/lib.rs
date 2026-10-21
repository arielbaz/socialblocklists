//! Liaison JNI pour `dev.geder.core.GederEngine` (application Android).
//!
//! Un handle regroupe le moteur (partagé par un `Mutex`) et, s'il tourne, le tunnel.
//! Le VpnService appelle ces fonctions depuis plusieurs threads ; la classe Kotlin
//! garantit qu'aucun appel n'est en cours pendant `nativeFree`.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

use ed25519_dalek::VerifyingKey;
use geder_core::{DenyReason, DnsPacketAction, DomainName, Engine, EngineConfig, PacketVerdict};
use geder_tunnel::{Events, Protect, ProtectedDialer, RunningTunnel, TunnelConfig};
use jni::objects::{GlobalRef, JByteArray, JClass, JObject, JObjectArray, JString, JValue};
use jni::sys::{jboolean, jbyteArray, jint, jlong, jstring, JNI_FALSE, JNI_TRUE};
use jni::{JNIEnv, JavaVM};

/// Codes renvoyés par `nativeClassifyPacket` (miroir de `GederEngine.kt`).
mod code {
    pub const ALLOW: i32 = 0;
    pub const DNS_QUERY: i32 = 1;
    pub const DENY_UNBOUND_IP: i32 = 10;
    pub const DENY_QUIC: i32 = 11;
    pub const DENY_DNS_OVER_TLS: i32 = 12;
    pub const DENY_FOREIGN_DNS: i32 = 13;
    pub const DENY_PROTOCOL: i32 = 14;
    pub const DENY_BLOCKED_SNI: i32 = 15;
    pub const DENY_ECH: i32 = 16;
    pub const DENY_MALFORMED: i32 = 17;
    pub const DENY_FRAGMENT: i32 = 18;
}

/// Premier octet du tableau renvoyé par `nativeHandleDnsPacket`.
mod dns_code {
    pub const FORWARD: u8 = 0;
    pub const REPLY: u8 = 1;
    pub const DROP: u8 = 2;
}

struct Shared {
    engine: Arc<Mutex<Engine>>,
    tunnel: Mutex<Option<RunningTunnel>>,
}

fn shared<'a>(handle: jlong) -> Option<&'a Shared> {
    // SAFETY : `handle` vient de `nativeNew` et n'est libéré que par `nativeFree`,
    // que la classe Kotlin appelle une seule fois, sous verrou exclusif.
    unsafe { (handle as *const Shared).as_ref() }
}

/// Verrou du moteur ; un verrou empoisonné garde l'état existant (refus par défaut).
fn lock(engine: &Mutex<Engine>) -> MutexGuard<'_, Engine> {
    engine.lock().unwrap_or_else(|e| e.into_inner())
}

fn with_engine<R>(handle: jlong, default: R, f: impl FnOnce(&mut Engine) -> R) -> R {
    match shared(handle) {
        Some(s) => f(&mut lock(&s.engine)),
        // Handle nul (moteur fermé) : réponse « refus » donnée par l'appelant.
        None => default,
    }
}

fn byte_array(env: &mut JNIEnv, data: &[u8]) -> jbyteArray {
    env.byte_array_from_slice(data).map(JByteArray::into_raw).unwrap_or(std::ptr::null_mut())
}

fn error_string(env: &mut JNIEnv, msg: Option<String>) -> jstring {
    match msg {
        None => JObject::null().into_raw(),
        // Si la création échoue, la JVM a une exception en attente : jamais un faux succès.
        Some(msg) => env.new_string(msg).map(JString::into_raw).unwrap_or(std::ptr::null_mut()),
    }
}

#[no_mangle]
pub extern "system" fn Java_dev_geder_core_GederEngine_nativeNew(
    mut env: JNIEnv,
    _class: JClass,
    keys: JObjectArray,
    resolver_v4: JByteArray,
    resolver_v6: JByteArray,
) -> jlong {
    #[cfg(target_os = "android")]
    android_logger::init_once(
        android_logger::Config::default().with_max_level(log::LevelFilter::Info).with_tag("GederCore"),
    );

    let mut trusted = Vec::new();
    let n = env.get_array_length(&keys).unwrap_or(0);
    for i in 0..n {
        let Ok(obj) = env.get_object_array_element(&keys, i) else { return 0 };
        let Ok(bytes) = env.convert_byte_array(JByteArray::from(obj)) else { return 0 };
        let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice()) else { return 0 };
        let Ok(key) = VerifyingKey::from_bytes(&arr) else { return 0 };
        trusted.push(key);
    }
    let mut config = EngineConfig::default();
    if let Ok(v4) = env.convert_byte_array(&resolver_v4) {
        if let Ok(o) = <[u8; 4]>::try_from(v4.as_slice()) {
            config.resolver_v4 = Ipv4Addr::from(o);
        }
    }
    if let Ok(v6) = env.convert_byte_array(&resolver_v6) {
        config.resolver_v6 = <[u8; 16]>::try_from(v6.as_slice()).ok().map(Ipv6Addr::from);
    }
    let shared = Shared { engine: Arc::new(Mutex::new(Engine::new(config, trusted))), tunnel: Mutex::new(None) };
    Box::into_raw(Box::new(shared)) as jlong
}

#[no_mangle]
pub extern "system" fn Java_dev_geder_core_GederEngine_nativeFree(_env: JNIEnv, _class: JClass, handle: jlong) {
    if handle != 0 {
        // SAFETY : voir `shared()` ; la classe Kotlin remet son handle à 0 juste avant.
        // Le tunnel éventuel est arrêté par le Drop de RunningTunnel.
        drop(unsafe { Box::from_raw(handle as *mut Shared) });
    }
}

/// Renvoie `null` si la liste est chargée, sinon le message d'erreur.
#[no_mangle]
pub extern "system" fn Java_dev_geder_core_GederEngine_nativeLoadList(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    data: JByteArray,
) -> jstring {
    let err = match env.convert_byte_array(&data) {
        Ok(bytes) => with_engine(handle, Some("moteur indisponible".to_owned()), |e| {
            e.load_list(&bytes).err().map(|err| err.to_string())
        }),
        Err(_) => Some("liste illisible".to_owned()),
    };
    error_string(&mut env, err)
}

#[no_mangle]
pub extern "system" fn Java_dev_geder_core_GederEngine_nativeIsDomainAllowed(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    name: JString,
) -> jboolean {
    let Ok(name) = env.get_string(&name) else { return JNI_FALSE };
    let name: String = name.into();
    if with_engine(handle, false, |e| e.is_domain_allowed(&name)) {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

#[no_mangle]
pub extern "system" fn Java_dev_geder_core_GederEngine_nativeClassifyPacket(
    env: JNIEnv,
    _class: JClass,
    handle: jlong,
    packet: JByteArray,
) -> jint {
    let Ok(bytes) = env.convert_byte_array(&packet) else { return code::DENY_MALFORMED };
    with_engine(handle, code::DENY_MALFORMED, |e| match e.classify_packet(&bytes, Instant::now()) {
        PacketVerdict::Allow { .. } => code::ALLOW,
        PacketVerdict::DnsQuery(_) => code::DNS_QUERY,
        PacketVerdict::Deny(reason) => match reason {
            DenyReason::UnboundIp => code::DENY_UNBOUND_IP,
            DenyReason::Quic => code::DENY_QUIC,
            DenyReason::DnsOverTls => code::DENY_DNS_OVER_TLS,
            DenyReason::ForeignDns => code::DENY_FOREIGN_DNS,
            DenyReason::Protocol(_) => code::DENY_PROTOCOL,
            DenyReason::BlockedSni(_) => code::DENY_BLOCKED_SNI,
            DenyReason::EncryptedClientHello => code::DENY_ECH,
            DenyReason::Malformed => code::DENY_MALFORMED,
            DenyReason::Fragment => code::DENY_FRAGMENT,
        },
    })
}

/// Traite un paquet IP adressé à notre résolveur (mode DNS). Format du tableau renvoyé :
/// - `[0, <requête DNS>]` : envoyer la requête au résolveur amont, puis appeler
///   `nativeCompleteDnsPacket` avec le paquet d'origine et la réponse ;
/// - `[1, n, <n octets : domaine bloqué>, <paquet IP>]` : écrire le paquet sur la TUN
///   (n = 0 si aucun domaine n'est à signaler) ;
/// - `[2]` : ignorer le paquet.
#[no_mangle]
pub extern "system" fn Java_dev_geder_core_GederEngine_nativeHandleDnsPacket(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    packet: JByteArray,
) -> jbyteArray {
    let Ok(bytes) = env.convert_byte_array(&packet) else {
        return byte_array(&mut env, &[dns_code::DROP]);
    };
    let action = with_engine(handle, DnsPacketAction::Drop, |e| e.handle_dns_packet(&bytes));
    let out = match action {
        DnsPacketAction::Forward(query) => [&[dns_code::FORWARD][..], &query].concat(),
        DnsPacketAction::Drop => vec![dns_code::DROP],
        DnsPacketAction::Reply { packet, blocked } => {
            let name = blocked.as_ref().map(|d| d.as_str().as_bytes()).unwrap_or(&[]);
            // ≤ 253 octets, garanti par DomainName.
            [&[dns_code::REPLY, name.len() as u8][..], name, &packet].concat()
        }
    };
    byte_array(&mut env, &out)
}

/// Lie les IP de la réponse amont et renvoie le paquet IP à écrire sur la TUN,
/// ou `null` si la réponse ne correspond pas à la requête.
#[no_mangle]
pub extern "system" fn Java_dev_geder_core_GederEngine_nativeCompleteDnsPacket(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    packet: JByteArray,
    response: JByteArray,
) -> jbyteArray {
    let (Ok(packet), Ok(response)) = (env.convert_byte_array(&packet), env.convert_byte_array(&response)) else {
        return std::ptr::null_mut();
    };
    match with_engine(handle, None, |e| e.complete_dns_packet(&packet, &response, Instant::now()).ok()) {
        Some(out) => byte_array(&mut env, &out),
        None => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "system" fn Java_dev_geder_core_GederEngine_nativePurge(_env: JNIEnv, _class: JClass, handle: jlong) {
    with_engine(handle, (), |e| e.purge(Instant::now()));
}

/// Rappels vers l'objet Kotlin `GederEngine.TunnelCallbacks`, depuis les threads du tunnel.
struct JavaCallbacks {
    vm: JavaVM,
    obj: GlobalRef,
}

impl JavaCallbacks {
    fn call<R>(&self, f: impl FnOnce(&mut JNIEnv, &JObject) -> jni::errors::Result<R>) -> Option<R> {
        // Les threads du runtime sont attachés une fois pour toutes (détachés à leur fin).
        let mut env = self.vm.attach_current_thread_permanently().ok()?;
        let result = f(&mut env, self.obj.as_obj());
        if env.exception_check().unwrap_or(false) {
            let _ = env.exception_clear();
            return None;
        }
        result.ok()
    }
}

struct JavaProtect(Arc<JavaCallbacks>);

impl Protect for JavaProtect {
    fn protect(&self, fd: i32) -> bool {
        self.0.call(|env, obj| env.call_method(obj, "protect", "(I)Z", &[JValue::Int(fd)])?.z()).unwrap_or(false)
    }
}

impl Events for JavaCallbacks {
    fn blocked_domain(&self, domain: &DomainName) {
        self.call(|env, obj| {
            let name = env.new_string(domain.as_str())?;
            env.call_method(obj, "onBlocked", "(Ljava/lang/String;)V", &[JValue::Object(&name)])?;
            Ok(())
        });
    }
}

/// Démarre le tunnel complet sur le descripteur TUN `fd` (dont il devient propriétaire).
/// `callbacks` implémente `protect(int): boolean` et `onBlocked(String)`.
/// Renvoie `null` si le tunnel tourne, sinon la raison de l'échec.
#[no_mangle]
pub extern "system" fn Java_dev_geder_core_GederEngine_nativeStartTunnel(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    fd: jint,
    mtu: jint,
    callbacks: JObject,
) -> jstring {
    let err = start_tunnel(&mut env, handle, fd, mtu, &callbacks).err();
    error_string(&mut env, err)
}

fn start_tunnel(env: &mut JNIEnv, handle: jlong, fd: jint, mtu: jint, callbacks: &JObject) -> Result<(), String> {
    let shared = shared(handle).ok_or("moteur indisponible")?;
    let mut slot = shared.tunnel.lock().unwrap_or_else(|e| e.into_inner());
    if slot.is_some() {
        return Err("tunnel déjà démarré".into());
    }
    let callbacks = Arc::new(JavaCallbacks {
        vm: env.get_java_vm().map_err(|e| e.to_string())?,
        obj: env.new_global_ref(callbacks).map_err(|e| e.to_string())?,
    });
    let config = TunnelConfig { mtu: u16::try_from(mtu).map_err(|_| "MTU invalide")?, ..Default::default() };
    let dialer = Arc::new(ProtectedDialer(JavaProtect(callbacks.clone())));
    let tunnel = RunningTunnel::spawn_from_fd(fd, shared.engine.clone(), dialer, callbacks, config)
        .map_err(|e| format!("démarrage du tunnel : {e}"))?;
    *slot = Some(tunnel);
    Ok(())
}

/// Arrête le tunnel s'il tourne (la TUN est fermée).
#[no_mangle]
pub extern "system" fn Java_dev_geder_core_GederEngine_nativeStopTunnel(_env: JNIEnv, _class: JClass, handle: jlong) {
    if let Some(shared) = shared(handle) {
        let tunnel = shared.tunnel.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(t) = tunnel {
            if let Err(e) = t.stop() {
                log::warn!("arrêt du tunnel : {e}");
            }
        }
    }
}

/// Test seulement : crée une TUN Linux `10.201.0.1/24` et renvoie son descripteur,
/// pour exercer `nativeStartTunnel` depuis une JVM de bureau.
#[cfg(all(feature = "jni-test", target_os = "linux"))]
#[no_mangle]
pub extern "system" fn Java_dev_geder_core_GederEngine_nativeTestCreateTun(_env: JNIEnv, _class: JClass) -> jint {
    use std::os::fd::IntoRawFd;
    let mut config = tun::Configuration::default();
    config.tun_name("geder-jni0").address((10, 201, 0, 1)).netmask((255, 255, 255, 0)).mtu(1500).up();
    tun::create(&config).map(|d| d.into_raw_fd()).unwrap_or(-1)
}

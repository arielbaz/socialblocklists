//! Liaison JNI pour `dev.geder.core.GederEngine` (application Android).
//!
//! Le moteur est protégé par un `Mutex` : le VpnService l'appelle depuis plusieurs
//! threads (lecture TUN, réponses DNS amont, minuterie de purge).

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;
use std::time::Instant;

use ed25519_dalek::VerifyingKey;
use jni::objects::{JByteArray, JClass, JObject, JObjectArray, JString};
use jni::sys::{jboolean, jbyteArray, jint, jlong, jstring, JNI_FALSE, JNI_TRUE};
use jni::JNIEnv;

use crate::engine::{DenyReason, DnsPacketAction, Engine, EngineConfig, PacketVerdict};

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

fn engine<'a>(handle: jlong) -> Option<&'a Mutex<Engine>> {
    // SAFETY : `handle` vient de `nativeNew` et n'est libéré que par `nativeFree`,
    // que la classe Kotlin appelle une seule fois après le dernier usage.
    unsafe { (handle as *const Mutex<Engine>).as_ref() }
}

fn with_engine<R>(handle: jlong, default: R, f: impl FnOnce(&mut Engine) -> R) -> R {
    match engine(handle).map(|m| m.lock()) {
        Some(Ok(mut e)) => f(&mut e),
        // Mutex empoisonné ou handle nul : on refuse (fail-closed) via la valeur par défaut.
        _ => default,
    }
}

fn byte_array(env: &mut JNIEnv, data: &[u8]) -> jbyteArray {
    env.byte_array_from_slice(data).map(JByteArray::into_raw).unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub extern "system" fn Java_dev_geder_core_GederEngine_nativeNew(
    mut env: JNIEnv,
    _class: JClass,
    keys: JObjectArray,
    resolver_v4: JByteArray,
    resolver_v6: JByteArray,
) -> jlong {
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
    Box::into_raw(Box::new(Mutex::new(Engine::new(config, trusted)))) as jlong
}

#[no_mangle]
pub extern "system" fn Java_dev_geder_core_GederEngine_nativeFree(_env: JNIEnv, _class: JClass, handle: jlong) {
    if handle != 0 {
        // SAFETY : voir `engine()` ; la classe Kotlin remet son handle à 0 juste avant.
        drop(unsafe { Box::from_raw(handle as *mut Mutex<Engine>) });
    }
}

/// Renvoie `null` si la liste est chargée, sinon le message d'erreur.
#[no_mangle]
pub extern "system" fn Java_dev_geder_core_GederEngine_nativeLoadList(
    env: JNIEnv,
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
    // Si la création de la chaîne échoue, la JVM a une exception en attente : jamais un faux succès.
    match err {
        None => JObject::null().into_raw(),
        Some(msg) => env.new_string(msg).map(JString::into_raw).unwrap_or(std::ptr::null_mut()),
    }
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

/// Traite un paquet IP adressé à notre résolveur. Format du tableau renvoyé :
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

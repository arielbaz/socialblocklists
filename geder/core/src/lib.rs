//! # geder-core
//!
//! Moteur de filtrage partagé de GEDER, identique sur toutes les plateformes.
//! Chaque OS ne fournit qu'un adaptateur natif (VpnService, WFP, Network Extension).
//!
//! Principes :
//! - **refus par défaut** : seul ce qui est sur une liste blanche signée passe ;
//! - **liaison DNS -> IP** : une connexion n'est ouverte que vers une IP que notre
//!   résolveur vient de renvoyer pour un domaine autorisé ;
//! - **aucun déchiffrement** : on lit seulement le DNS et le SNI TLS en clair.

pub mod binding;
pub mod dns;
pub mod domain;
pub mod engine;
pub mod list;
pub mod packet;
pub mod pin;
pub mod tls;

#[cfg(feature = "android")]
mod ffi_android;

pub use domain::{DomainName, DomainSet, Rule, RuleKind};
pub use engine::{DenyReason, DnsAction, DnsPacketAction, Engine, EngineConfig, EngineError, PacketVerdict, Verdict};
pub use list::AllowList;
pub use packet::Transport;

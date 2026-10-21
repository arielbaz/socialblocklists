//! geder-list : outil serveur pour les listes blanches GEDER.
//!
//! ```text
//! geder-list keygen <clé-secrète> <clé-publique>
//! geder-list check  <liste.txt>...
//! geder-list sign   <clé-secrète> <liste.txt> <sortie.txt>
//! geder-list verify <clé-publique> <liste-signée.txt>
//! geder-list match  <liste.txt> <domaine>...
//! ```
//!
//! La clé secrète ne doit jamais être commitée ni copiée sur un poste de développeur :
//! elle vit dans le coffre de secrets du serveur de publication.

use std::fs;
use std::process::ExitCode;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ed25519_dalek::{SigningKey, VerifyingKey};
use geder_core::{list, DomainName, DomainSet};
use rand_core::OsRng;

const USAGE: &str = "usage :
  geder-list keygen <clé-secrète> <clé-publique>
  geder-list check  <liste.txt>...
  geder-list sign   <clé-secrète> <liste.txt> <sortie.txt>
  geder-list verify <clé-publique> <liste-signée.txt>
  geder-list match  <liste.txt> <domaine>...";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = match args.as_slice() {
        ["keygen", secret, public] => keygen(secret, public),
        ["check", files @ ..] if !files.is_empty() => check(files),
        ["sign", secret, input, output] => sign(secret, input, output),
        ["verify", public, input] => verify(public, input),
        ["match", input, domains @ ..] if !domains.is_empty() => matches(input, domains),
        _ => Err(USAGE.to_owned()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

fn read(path: &str) -> Result<String, String> {
    fs::read_to_string(path).map_err(|e| format!("{path} : {e}"))
}

fn read_key_bytes(path: &str) -> Result<[u8; 32], String> {
    let raw = B64.decode(read(path)?.trim()).map_err(|_| format!("{path} : clé non base64"))?;
    raw.try_into().map_err(|_| format!("{path} : une clé fait 32 octets"))
}

fn keygen(secret: &str, public: &str) -> Result<(), String> {
    if fs::metadata(secret).is_ok() {
        return Err(format!("{secret} existe déjà : refus d'écraser une clé"));
    }
    let key = SigningKey::generate(&mut OsRng);
    write_private(secret, &format!("{}\n", B64.encode(key.to_bytes())))?;
    fs::write(public, format!("{}\n", B64.encode(key.verifying_key().to_bytes())))
        .map_err(|e| format!("{public} : {e}"))?;
    println!("clé secrète : {secret} (à mettre dans le coffre, jamais dans Git)");
    println!("clé publique : {public} (à intégrer dans les applis)");
    Ok(())
}

#[cfg(unix)]
fn write_private(path: &str, content: &str) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("{path} : {e}"))?;
    f.write_all(content.as_bytes()).map_err(|e| format!("{path} : {e}"))
}

#[cfg(not(unix))]
fn write_private(path: &str, content: &str) -> Result<(), String> {
    fs::write(path, content).map_err(|e| format!("{path} : {e}"))
}

fn check(files: &[&str]) -> Result<(), String> {
    let mut failed = false;
    for path in files {
        match list::parse_unsigned(&read(path)?) {
            Ok(l) => println!("{path} : ok — « {} » v{}, {} règles", l.name, l.version, l.rules.len()),
            Err(e) => {
                eprintln!("{path} : {e}");
                failed = true;
            }
        }
    }
    if failed {
        Err("au moins une liste est invalide".into())
    } else {
        Ok(())
    }
}

fn sign(secret: &str, input: &str, output: &str) -> Result<(), String> {
    let key = SigningKey::from_bytes(&read_key_bytes(secret)?);
    let signed = list::sign(&read(input)?, &key).map_err(|e| format!("{input} : {e}"))?;
    fs::write(output, signed).map_err(|e| format!("{output} : {e}"))?;
    println!("{output} : signée");
    Ok(())
}

fn verify(public: &str, input: &str) -> Result<(), String> {
    let key = VerifyingKey::from_bytes(&read_key_bytes(public)?).map_err(|_| format!("{public} : clé invalide"))?;
    let data = fs::read(input).map_err(|e| format!("{input} : {e}"))?;
    let l = list::verify(&data, &[key]).map_err(|e| format!("{input} : {e}"))?;
    println!("{input} : signature valide — « {} » v{}, {} règles", l.name, l.version, l.rules.len());
    Ok(())
}

fn matches(input: &str, domains: &[&str]) -> Result<(), String> {
    let l = list::parse_unsigned(&read(input)?).map_err(|e| format!("{input} : {e}"))?;
    let set: DomainSet = l.rules.iter().collect();
    for d in domains {
        let verdict = match DomainName::parse(d) {
            Ok(name) if set.contains(&name) => "autorisé",
            Ok(_) => "bloqué",
            Err(_) => "nom invalide",
        };
        println!("{d} : {verdict}");
    }
    Ok(())
}

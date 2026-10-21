//! Noms de domaine : normalisation et ensemble de règles en trie de suffixes.
//!
//! Les labels sont stockés à l'envers (`www.google.com` -> `com`, `google`, `www`),
//! ce qui donne une recherche en O(nombre de labels) sans faux positifs, contrairement
//! à une recherche de sous-chaînes (Aho-Corasick) qui confondrait `evilgoogle.com`
//! et `google.com`.

use std::collections::HashMap;
use std::fmt;

/// Longueur maximale d'un nom de domaine (RFC 1035), sans le point final.
pub const MAX_NAME_LEN: usize = 253;
/// Longueur maximale d'un label (RFC 1035).
pub const MAX_LABEL_LEN: usize = 63;

/// Nom de domaine validé : ASCII minuscule, sans point final.
/// Les noms internationalisés doivent être fournis en punycode (`xn--...`).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DomainName(String);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DomainError {
    #[error("nom de domaine vide")]
    Empty,
    #[error("nom de domaine trop long")]
    TooLong,
    #[error("label vide ou trop long")]
    BadLabel,
    #[error("caractère interdit dans un nom de domaine")]
    BadChar,
}

impl DomainName {
    pub fn parse(input: &str) -> Result<Self, DomainError> {
        let name = input.strip_suffix('.').unwrap_or(input);
        if name.is_empty() {
            return Err(DomainError::Empty);
        }
        if name.len() > MAX_NAME_LEN {
            return Err(DomainError::TooLong);
        }
        let mut out = String::with_capacity(name.len());
        for (i, label) in name.split('.').enumerate() {
            if label.is_empty() || label.len() > MAX_LABEL_LEN {
                return Err(DomainError::BadLabel);
            }
            if i > 0 {
                out.push('.');
            }
            for c in label.chars() {
                // `_` est toléré : il apparaît dans des noms techniques (`_dmarc`, SRV).
                if !(c.is_ascii_alphanumeric() || c == '-' || c == '_') {
                    return Err(DomainError::BadChar);
                }
                out.push(c.to_ascii_lowercase());
            }
        }
        Ok(DomainName(out))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Labels du plus général au plus précis : `com`, `google`, `www`.
    pub fn labels_rev(&self) -> impl Iterator<Item = &str> {
        self.0.rsplit('.')
    }
}

impl fmt::Display for DomainName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Portée d'une règle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleKind {
    /// `example.com` : ce nom exact uniquement.
    Exact,
    /// `*.example.com` : tous les sous-domaines, mais pas `example.com` lui-même.
    Subdomains,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    pub domain: DomainName,
    pub kind: RuleKind,
}

impl Rule {
    /// Analyse une ligne de règle : `example.com` ou `*.example.com`.
    pub fn parse(input: &str) -> Result<Self, DomainError> {
        match input.strip_prefix("*.") {
            Some(rest) => Ok(Rule { domain: DomainName::parse(rest)?, kind: RuleKind::Subdomains }),
            None => Ok(Rule { domain: DomainName::parse(input)?, kind: RuleKind::Exact }),
        }
    }
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            RuleKind::Exact => write!(f, "{}", self.domain),
            RuleKind::Subdomains => write!(f, "*.{}", self.domain),
        }
    }
}

#[derive(Default, Debug, Clone)]
struct Node {
    children: HashMap<Box<str>, Node>,
    exact: bool,
    subdomains: bool,
}

/// Ensemble de règles de domaines.
#[derive(Default, Debug, Clone)]
pub struct DomainSet {
    root: Node,
    len: usize,
}

impl DomainSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn insert(&mut self, rule: &Rule) {
        let mut node = &mut self.root;
        for label in rule.domain.labels_rev() {
            node = node.children.entry(label.into()).or_default();
        }
        let flag = match rule.kind {
            RuleKind::Exact => &mut node.exact,
            RuleKind::Subdomains => &mut node.subdomains,
        };
        if !*flag {
            *flag = true;
            self.len += 1;
        }
    }

    pub fn contains(&self, name: &DomainName) -> bool {
        let mut node = &self.root;
        let mut labels = name.labels_rev().peekable();
        while let Some(label) = labels.next() {
            match node.children.get(label) {
                Some(child) => node = child,
                None => return false,
            }
            if labels.peek().is_none() {
                return node.exact;
            }
            // Il reste au moins un label : nous sommes sur un sous-domaine de `node`.
            if node.subdomains {
                return true;
            }
        }
        false
    }
}

impl<'a> FromIterator<&'a Rule> for DomainSet {
    fn from_iter<I: IntoIterator<Item = &'a Rule>>(iter: I) -> Self {
        let mut set = DomainSet::new();
        for rule in iter {
            set.insert(rule);
        }
        set
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(s: &str) -> DomainName {
        DomainName::parse(s).unwrap()
    }

    fn set(rules: &[&str]) -> DomainSet {
        let rules: Vec<Rule> = rules.iter().map(|r| Rule::parse(r).unwrap()).collect();
        rules.iter().collect()
    }

    #[test]
    fn normalizes_case_and_trailing_dot() {
        assert_eq!(name("WWW.Example.COM.").as_str(), "www.example.com");
    }

    #[test]
    fn rejects_invalid_names() {
        assert_eq!(DomainName::parse(""), Err(DomainError::Empty));
        assert_eq!(DomainName::parse("."), Err(DomainError::Empty));
        assert_eq!(DomainName::parse("a..b"), Err(DomainError::BadLabel));
        assert_eq!(DomainName::parse("exa mple.com"), Err(DomainError::BadChar));
        assert_eq!(DomainName::parse("exämple.com"), Err(DomainError::BadChar));
        assert_eq!(DomainName::parse(&"a".repeat(64)), Err(DomainError::BadLabel));
        let long = vec!["abcdefghi"; 26].join(".");
        assert_eq!(DomainName::parse(&long), Err(DomainError::TooLong));
    }

    #[test]
    fn exact_rule_matches_only_that_name() {
        let s = set(&["example.com"]);
        assert!(s.contains(&name("example.com")));
        assert!(!s.contains(&name("www.example.com")));
        assert!(!s.contains(&name("com")));
        assert!(!s.contains(&name("evilexample.com")));
    }

    #[test]
    fn wildcard_matches_subdomains_but_not_apex() {
        let s = set(&["*.example.com"]);
        assert!(s.contains(&name("www.example.com")));
        assert!(s.contains(&name("a.b.example.com")));
        assert!(!s.contains(&name("example.com")));
        assert!(!s.contains(&name("example.com.evil.net")));
    }

    #[test]
    fn exact_and_wildcard_combine() {
        let s = set(&["example.com", "*.example.com", "*.cdn.other.org"]);
        assert!(s.contains(&name("example.com")));
        assert!(s.contains(&name("x.example.com")));
        assert!(s.contains(&name("img.cdn.other.org")));
        assert!(!s.contains(&name("cdn.other.org")));
        assert!(!s.contains(&name("other.org")));
        assert_eq!(s.len(), 3);
    }

    #[test]
    fn duplicates_are_counted_once() {
        let s = set(&["example.com", "EXAMPLE.com.", "*.a.b", "*.a.b"]);
        assert_eq!(s.len(), 2);
    }
}

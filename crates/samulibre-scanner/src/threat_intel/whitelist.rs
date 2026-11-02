use std::collections::HashSet;

/// Lista de hashes y valores protegidos que NUNCA deben marcarse como maliciosos
pub struct ThreatWhitelist {
    protected_hashes: HashSet<&'static str>,
    protected_domains: HashSet<&'static str>,
    protected_ips: HashSet<&'static str>,
}

impl Default for ThreatWhitelist {
    fn default() -> Self {
        let mut protected_hashes = HashSet::new();
        // Hash de archivo vacío (SHA-256)
        protected_hashes.insert("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        // Hash nulo
        protected_hashes.insert("0000000000000000000000000000000000000000000000000000000000000000");
        // Hash MD5 vacío
        protected_hashes.insert("d41d8cd98f00b204e9800998ecf8427e");

        let mut protected_domains = HashSet::new();
        protected_domains.insert("localhost");
        protected_domains.insert("kernel.org");
        protected_domains.insert("ubuntu.com");
        protected_domains.insert("debian.org");
        protected_domains.insert("redhat.com");
        protected_domains.insert("fedoraproject.org");
        protected_domains.insert("archlinux.org");
        protected_domains.insert("garudalinux.org");
        protected_domains.insert("github.com");
        protected_domains.insert("crates.io");
        protected_domains.insert("google.com");
        protected_domains.insert("cloudflare.com");
        protected_domains.insert("quad9.net");

        let mut protected_ips = HashSet::new();
        protected_ips.insert("127.0.0.1");
        protected_ips.insert("::1");
        protected_ips.insert("0.0.0.0");
        protected_ips.insert("8.8.8.8");
        protected_ips.insert("1.1.1.1");
        protected_ips.insert("9.9.9.9");

        Self {
            protected_hashes,
            protected_domains,
            protected_ips,
        }
    }
}

impl ThreatWhitelist {
    /// Determina si un hash está protegido y debe ser descartado
    pub fn is_hash_whitelisted(&self, hash: &str) -> bool {
        self.protected_hashes.contains(hash.to_lowercase().as_str())
    }

    /// Determina si un dominio o URL legítimo fue incluido accidentalmente en un feed
    pub fn is_domain_whitelisted(&self, domain: &str) -> bool {
        let clean = domain.trim().to_lowercase();
        self.protected_domains.iter().any(|&d| clean == d || clean.ends_with(&format!(".{}", d)))
    }

    /// Determina si una IP del sistema o DNS público fue reportada
    pub fn is_ip_whitelisted(&self, ip: &str) -> bool {
        self.protected_ips.contains(ip.trim())
    }
}

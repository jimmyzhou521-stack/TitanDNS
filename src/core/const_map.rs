// Compile-time Perfect Hash Map
// Zero runtime overhead for static lookups

use phf::phf_map;

/// Commonly blocked advertising domains (compile-time perfect hash)
/// O(1) lookup with zero hash computation overhead
pub static BLOCKED_AD_DOMAINS: phf::Map<&'static str, ()> = phf_map! {
    "ads.google.com" => (),
    "doubleclick.net" => (),
    "googleadservices.com" => (),
    "googlesyndication.com" => (),
    "adservice.google.com" => (),
    "pagead2.googlesyndication.com" => (),
    "afs.googlesyndication.com" => (),
    "www.googleadservices.com" => (),
    "www.google-analytics.com" => (),
    "ssl.google-analytics.com" => (),
    "stats.g.doubleclick.net" => (),
    "ad.doubleclick.net" => (),
    "static.doubleclick.net" => (),
    "m.doubleclick.net" => (),
    "mediavisor.doubleclick.net" => (),
    "pubads.g.doubleclick.net" => (),
    "securepubads.g.doubleclick.net" => (),
    "facebook.com" => (),
    "www.facebook.com" => (),
    "connect.facebook.net" => (),
    "graph.facebook.com" => (),
    "pixel.facebook.com" => (),
    "b-api.facebook.com" => (),
    "b-graph.facebook.com" => (),
};

/// Known tracker domains
pub static BLOCKED_TRACKER_DOMAINS: phf::Map<&'static str, ()> = phf_map! {
    "analytics.google.com" => (),
    "www.googletagmanager.com" => (),
    "www.googletagservices.com" => (),
    "googletagmanager.com" => (),
    "googletagservices.com" => (),
    "google-analytics.com" => (),
    "ssl.google-analytics.com" => (),
    "analytics.twitter.com" => (),
    "scontent.xx.fbcdn.net" => (),
    "scontent-lax3-1.xx.fbcdn.net" => (),
};

/// Check if a domain is in the blocked list
/// Zero-cost abstraction: inlined and optimized at compile time
#[inline]
pub fn is_ad_domain(domain: &str) -> bool {
    BLOCKED_AD_DOMAINS.contains_key(domain)
}

#[inline]
pub fn is_tracker_domain(domain: &str) -> bool {
    BLOCKED_TRACKER_DOMAINS.contains_key(domain)
}

#[inline]
pub fn is_blocked_domain(domain: &str) -> bool {
    is_ad_domain(domain) || is_tracker_domain(domain)
}

/// Commonly used nameservers (for fast validation)
pub static KNOWN_NAMESERVERS: phf::Map<&'static str, &'static str> = phf_map! {
    "8.8.8.8" => "Google Public DNS",
    "8.8.4.4" => "Google Public DNS",
    "1.1.1.1" => "Cloudflare DNS",
    "1.0.0.1" => "Cloudflare DNS",
    "9.9.9.9" => "Quad9 DNS",
    "149.112.112.112" => "Quad9 DNS",
    "208.67.222.222" => "OpenDNS",
    "208.67.220.220" => "OpenDNS",
    "64.6.64.6" => "Verisign DNS",
    "64.6.65.6" => "Verisign DNS",
};

#[inline]
pub fn get_nameserver_name(ip: &str) -> Option<&'static str> {
    KNOWN_NAMESERVERS.get(ip).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ad_domain_lookup() {
        assert!(is_ad_domain("ads.google.com"));
        assert!(is_ad_domain("doubleclick.net"));
        assert!(!is_ad_domain("example.com"));
    }

    #[test]
    fn test_tracker_domain_lookup() {
        assert!(is_tracker_domain("analytics.google.com"));
        assert!(!is_tracker_domain("example.com"));
    }

    #[test]
    fn test_blocked_domain() {
        assert!(is_blocked_domain("ads.google.com"));
        assert!(is_blocked_domain("analytics.google.com"));
        assert!(!is_blocked_domain("example.com"));
    }

    #[test]
    fn test_nameserver_lookup() {
        assert_eq!(get_nameserver_name("8.8.8.8"), Some("Google Public DNS"));
        assert_eq!(get_nameserver_name("1.1.1.1"), Some("Cloudflare DNS"));
        assert_eq!(get_nameserver_name("192.168.1.1"), None);
    }

    #[bench]
    #[cfg(feature = "bench")]
    fn bench_phf_lookup(b: &mut Bencher) {
        b.iter(|| {
            is_blocked_domain("ads.google.com")
        });
    }
}

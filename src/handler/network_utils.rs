use std::borrow::Cow;

#[inline]
fn strip_special_schemes(url: &str) -> &str {
    let url = url.strip_prefix("blob:").unwrap_or(url);
    url.strip_prefix("filesystem:").unwrap_or(url)
}

/// Returns (host_without_port, rest_starting_at_/ ? # or empty)
/// Robust: handles protocol-relative, userinfo, IPv6 literals, ports.
#[inline]
pub fn host_and_rest(url: &str) -> Option<(&str, &str)> {
    let url = strip_special_schemes(url);

    let host_start = if let Some(pos) = url.find("://") {
        pos + 3
    } else if url.starts_with("//") {
        2
    } else {
        return None;
    };

    // End of authority (first / ? # after host_start)
    let mut rest_start = url.len();
    if let Some(i) = url[host_start..].find('/') {
        rest_start = host_start + i;
    }
    if let Some(i) = url[host_start..].find('?') {
        rest_start = rest_start.min(host_start + i);
    }
    if let Some(i) = url[host_start..].find('#') {
        rest_start = rest_start.min(host_start + i);
    }

    let authority = &url[host_start..rest_start];
    if authority.is_empty() {
        return None;
    }

    // Drop userinfo if present: user:pass@host
    let authority = authority.rsplit('@').next().unwrap_or(authority);

    // IPv6: [::1]:8080
    if authority.as_bytes().first() == Some(&b'[') {
        let close = authority.find(']')?;
        let host = &authority[1..close];
        return Some((host, &url[rest_start..]));
    }

    // IPv4/hostname: host:port
    let host_end = authority.find(':').unwrap_or(authority.len());
    let host = &authority[..host_end];
    if host.is_empty() {
        return None;
    }

    Some((host, &url[rest_start..]))
}

#[inline]
fn eq_ignore_ascii_case(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.as_bytes()
            .iter()
            .zip(b.as_bytes().iter())
            .all(|(x, y)| x.to_ascii_lowercase() == y.to_ascii_lowercase())
}

#[inline]
fn ends_with_ignore_ascii_case(hay: &str, suf: &str) -> bool {
    if suf.len() > hay.len() {
        return false;
    }
    let a = &hay.as_bytes()[hay.len() - suf.len()..];
    let b = suf.as_bytes();
    a.iter()
        .zip(b.iter())
        .all(|(x, y)| x.to_ascii_lowercase() == y.to_ascii_lowercase())
}

/// Host matches base if host == base OR host ends with ".{base}" (case-insensitive),
/// with a required dot boundary to prevent "evil-logrocket.com" matching "logrocket.com".
#[inline]
pub fn host_is_subdomain_of(host: &str, base: &str) -> bool {
    let host = host.trim_end_matches('.');
    let base = base.trim_end_matches('.');

    if base.is_empty() {
        return false;
    }

    if eq_ignore_ascii_case(host, base) {
        return true;
    }

    if host.len() <= base.len() {
        return false;
    }

    let dot_pos = host.len() - base.len() - 1;
    host.as_bytes().get(dot_pos) == Some(&b'.') && ends_with_ignore_ascii_case(host, base)
}

/// PURE: Given a base domain (already computed) and a URL, returns the “relative” path
/// for same-site/subdomain URLs, otherwise returns the original URL.
#[inline]
pub fn rel_for_ignore_script<'a>(base_domain: &str, url: &'a str) -> Cow<'a, str> {
    if url.starts_with('/') {
        return Cow::Borrowed(url);
    }

    let base = base_domain.trim_end_matches('.');
    if base.is_empty() {
        return Cow::Borrowed(url);
    }

    if let Some((host, rest)) = host_and_rest(url) {
        if host_is_subdomain_of(host, base) {
            // Convert same-site absolute URL into a path-like string.
            if rest.starts_with('/') {
                return Cow::Borrowed(rest);
            }
            // e.g. "https://x.com?y" or "https://x.com#y"
            return Cow::Borrowed("/");
        }
    }

    Cow::Borrowed(url)
}

#[inline]
/// Common cc.
fn is_common_cc_sld(sld: &str) -> bool {
    let s = sld.as_bytes();
    match s.len() {
        2 => matches!(
            [s[0].to_ascii_lowercase(), s[1].to_ascii_lowercase()],
            // very common 2-letter buckets (JP uses a lot of these)
            [b'c', b'o'] | // co
            [b'a', b'c'] | // ac
            [b'g', b'o'] | // go
            [b'o', b'r'] | // or
            [b'n', b'e'] | // ne
            [b'e', b'd'] | // ed
            [b'g', b'r'] | // gr
            [b'l', b'g'] | // lg
            [b'a', b'd'] // ad
        ),
        3 => matches!(
            [
                s[0].to_ascii_lowercase(),
                s[1].to_ascii_lowercase(),
                s[2].to_ascii_lowercase()
            ],
            // globally common
            [b'c', b'o', b'm'] | // com
            [b'n', b'e', b't'] | // net
            [b'o', b'r', b'g'] | // org
            [b'g', b'o', b'v'] | // gov
            [b'e', b'd', b'u'] | // edu
            [b'm', b'i', b'l'] | // mil
            [b'n', b'i', b'c'] | // nic
            [b's', b'c', b'h'] | // sch
            // MX / some LATAM
            [b'g', b'o', b'b'] // gob
        ),
        4 => matches!(
            [
                s[0].to_ascii_lowercase(),
                s[1].to_ascii_lowercase(),
                s[2].to_ascii_lowercase(),
                s[3].to_ascii_lowercase()
            ],
            [b'g', b'o', b'u', b'v'] // gouv (seen in some places)
        ),
        _ => false,
    }
}

#[inline]
/// Get the base domain from a host.
pub fn base_domain_from_host(host: &str) -> &str {
    let mut h = host.trim_end_matches('.');
    if let Some(x) = h.strip_prefix("www.") {
        h = x;
    }
    if let Some(x) = h.strip_prefix("m.") {
        h = x;
    }

    // Find last two dots (positions)
    let last_dot = match h.rfind('.') {
        Some(p) => p,
        None => return h,
    };
    let prev_dot = match h[..last_dot].rfind('.') {
        Some(p) => p,
        None => return h,
    }; // only 1 dot => return host

    // last label (tld)
    let tld = &h[last_dot + 1..];
    let sld = &h[prev_dot + 1..last_dot]; // second-level (or suffix-part)
    let last2 = &h[prev_dot + 1..]; // "example.com" or "co.uk"

    // If it looks like a 2-level public suffix, return last 3 labels
    if tld.len() == 2 {
        let sld_is_common = is_common_cc_sld(sld);

        if sld_is_common {
            if let Some(prev2_dot) = h[..prev_dot].rfind('.') {
                return &h[prev2_dot + 1..];
            }
        }
    }

    last2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_match_basic_and_subdomains() {
        let base = "logrocket.com";

        assert!(host_is_subdomain_of("logrocket.com", base));
        assert!(host_is_subdomain_of("staging.logrocket.com", base));
        assert!(host_is_subdomain_of("a.b.c.logrocket.com", base));

        // case-insensitive
        assert!(host_is_subdomain_of(
            "StAgInG.LoGrOcKeT.CoM",
            "LOGROCKET.COM"
        ));
    }

    #[test]
    fn test_domain_match_no_false_positives() {
        let base = "logrocket.com";

        // must be dot-boundary
        assert!(!host_is_subdomain_of("evil-logrocket.com", base));
        assert!(!host_is_subdomain_of("logrocket.com.evil.com", base));
        assert!(!host_is_subdomain_of("staginglogrocket.com", base));
        assert!(!host_is_subdomain_of("logrocket.co", base));
    }

    #[test]
    fn test_host_and_rest_handles_userinfo_port_ipv6() {
        let (h, rest) =
            host_and_rest("https://user:pass@staging.logrocket.com:8443/a.js?x=1#y").unwrap();
        assert_eq!(h, "staging.logrocket.com");
        assert_eq!(rest, "/a.js?x=1#y");

        let (h, rest) = host_and_rest("http://[::1]:8080/path").unwrap();
        assert_eq!(h, "::1");
        assert_eq!(rest, "/path");
    }

    #[test]
    fn test_rel_for_ignore_script_logrocket_example() {
        let base = "logrocket.com";

        let main = "https://logrocket.com/careers";
        assert_eq!(rel_for_ignore_script(base, main).as_ref(), "/careers");

        let script = "https://staging.logrocket.com/LogRocket.min.js";
        assert_eq!(
            rel_for_ignore_script(base, script).as_ref(),
            "/LogRocket.min.js"
        );

        // Different site stays absolute
        let other = "https://cdn.other.com/app.js";
        assert_eq!(rel_for_ignore_script(base, other).as_ref(), other);

        // Root-relative stays as-is
        assert_eq!(
            rel_for_ignore_script(base, "/static/app.js").as_ref(),
            "/static/app.js"
        );
    }

    #[test]
    fn test_rel_for_ignore_script_query_only_same_site() {
        let base = "example.com";
        let u = "https://sub.example.com?x=1";
        assert_eq!(rel_for_ignore_script(base, u).as_ref(), "/");
    }

    #[test]
    fn test_rel_for_ignore_script_special_schemes() {
        let base = "example.com";
        let u = "blob:https://example.com/path/to/blob";
        assert_eq!(rel_for_ignore_script(base, u).as_ref(), "/path/to/blob");
    }
}

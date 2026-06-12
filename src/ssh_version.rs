use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenSshVersion {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    pub raw: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct KnownCveFinding {
    pub cve_id: String,
    pub severity: String,
    pub title: String,
    pub affected_through: String,
    pub recommendation: String,
}

pub fn parse_openssh_banner(banner: Option<&str>) -> Option<OpenSshVersion> {
    let banner = banner?;
    let marker = "OpenSSH_";
    let start = banner.find(marker)? + marker.len();
    let version_part = banner[start..]
        .split_whitespace()
        .next()?
        .split('-')
        .next()?;
    parse_openssh_version_token(version_part)
}

pub fn parse_openssh_version_token(token: &str) -> Option<OpenSshVersion> {
    let token = token.trim_start_matches('v');
    let (numbers, patch_suffix) = token.split_once('p').unwrap_or((token, ""));
    let mut parts = numbers.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next().unwrap_or("0").parse().ok()?;
    let patch = if patch_suffix.is_empty() {
        parts.next().unwrap_or("0").parse().ok()?
    } else {
        patch_suffix.parse().ok()?
    };
    Some(OpenSshVersion {
        major,
        minor,
        patch,
        raw: token.to_string(),
    })
}

pub fn version_lte(left: &OpenSshVersion, right: &(u64, u64, u64)) -> bool {
    (left.major, left.minor, left.patch) <= *right
}

pub fn known_cves_for_version(version: &OpenSshVersion) -> Vec<KnownCveFinding> {
    let mut findings = Vec::new();
    for rule in EMBEDDED_OPENSSH_CVE_RULES {
        if version_lte(version, &rule.affected_through) {
            findings.push(KnownCveFinding {
                cve_id: rule.cve_id.to_string(),
                severity: rule.severity.to_string(),
                title: rule.title.to_string(),
                affected_through: format!(
                    "{}.{}.{}",
                    rule.affected_through.0,
                    rule.affected_through.1,
                    rule.affected_through.2
                ),
                recommendation: rule.recommendation.to_string(),
            });
        }
    }
    findings
}

struct OpenSshCveRule {
    cve_id: &'static str,
    severity: &'static str,
    title: &'static str,
    affected_through: (u64, u64, u64),
    recommendation: &'static str,
}

const EMBEDDED_OPENSSH_CVE_RULES: &[OpenSshCveRule] = &[
    OpenSshCveRule {
        cve_id: "CVE-2023-38408",
        severity: "HIGH",
        title: "OpenSSH PKCS#11 provider remote code execution",
        affected_through: (9, 3, 0),
        recommendation: "Upgrade OpenSSH to 9.3p2 or later.",
    },
    OpenSshCveRule {
        cve_id: "CVE-2023-28531",
        severity: "CRITICAL",
        title: "OpenSSH agent forwarding double-free",
        affected_through: (9, 2, 0),
        recommendation: "Upgrade OpenSSH to 9.2p1 or later.",
    },
    OpenSshCveRule {
        cve_id: "CVE-2021-41617",
        severity: "HIGH",
        title: "OpenSSH privilege escalation via user/group modification",
        affected_through: (8, 7, 0),
        recommendation: "Upgrade OpenSSH to 8.8 or later.",
    },
    OpenSshCveRule {
        cve_id: "CVE-2020-15778",
        severity: "MEDIUM",
        title: "OpenSSH scp command injection",
        affected_through: (8, 3, 0),
        recommendation: "Upgrade OpenSSH to 8.4 or later and avoid untrusted scp arguments.",
    },
    OpenSshCveRule {
        cve_id: "CVE-2018-15473",
        severity: "MEDIUM",
        title: "OpenSSH username enumeration",
        affected_through: (7, 7, 0),
        recommendation: "Upgrade OpenSSH to 7.8 or later.",
    },
    OpenSshCveRule {
        cve_id: "CVE-2016-6210",
        severity: "HIGH",
        title: "OpenSSH password timing attack",
        affected_through: (7, 2, 0),
        recommendation: "Upgrade OpenSSH to 7.3 or later.",
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_openssh_banner() {
        let version = parse_openssh_banner(Some("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"))
            .expect("version");
        assert_eq!(version.major, 8);
        assert_eq!(version.minor, 9);
        assert_eq!(version.patch, 1);
    }

    #[test]
    fn flags_known_cves_for_old_versions() {
        let version = parse_openssh_version_token("7.4p1").expect("version");
        let findings = known_cves_for_version(&version);
        assert!(findings.iter().any(|finding| finding.cve_id == "CVE-2018-15473"));
    }
}

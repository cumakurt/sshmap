use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct HostContext {
    pub host_id: i64,
    pub environment: Option<String>,
    pub criticality: Option<String>,
    pub ssh_open: bool,
    pub os_family: Option<String>,
    pub os_version: Option<String>,
}

impl HostContext {
    pub fn context_multiplier(&self) -> f64 {
        let mut multiplier: f64 = 1.0;

        if let Some(environment) = self.environment.as_deref() {
            let normalized = environment.to_ascii_lowercase();
            if matches_environment(&normalized, &["production", "prod", "live", "prd"]) {
                multiplier += 0.35;
            } else if matches_environment(&normalized, &["staging", "stage", "uat", "preprod"]) {
                multiplier += 0.15;
            } else if matches_environment(&normalized, &["dev", "development", "lab", "test", "sandbox"]) {
                multiplier -= 0.25;
            }
        }

        if let Some(criticality) = self.criticality.as_deref() {
            let normalized = criticality.to_ascii_lowercase();
            if matches_environment(&normalized, &["critical", "high", "tier0", "tier1"]) {
                multiplier += 0.3;
            } else if matches_environment(&normalized, &["low", "tier3", "nonprod"]) {
                multiplier -= 0.15;
            }
        }

        if self.ssh_open {
            multiplier += 0.1;
        }

        if self
            .os_family
            .as_deref()
            .is_some_and(|value| value.eq_ignore_ascii_case("linux"))
            && self
                .os_version
                .as_deref()
                .is_some_and(|value| value.contains("6.") || value.contains("7."))
        {
            multiplier += 0.05;
        }

        multiplier.clamp(0.5, 2.0)
    }

    pub fn is_production_exposed(&self) -> bool {
        self.ssh_open
            && self.environment.as_deref().is_some_and(|value| {
                let normalized = value.to_ascii_lowercase();
                matches_environment(&normalized, &["production", "prod", "live", "prd"])
            })
    }
}

pub fn build_host_context_map(
    hosts: &[crate::models::HostContextRecord],
) -> BTreeMap<i64, HostContext> {
    hosts
        .iter()
        .map(|host| {
            (
                host.host_id,
                HostContext {
                    host_id: host.host_id,
                    environment: host.environment.clone(),
                    criticality: host.criticality.clone(),
                    ssh_open: host.ssh_open,
                    os_family: host.os_family.clone(),
                    os_version: host.os_version.clone(),
                },
            )
        })
        .collect()
}

pub fn adjust_severity(base: &str, multiplier: f64) -> String {
    let levels = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
    let Some(mut index) = levels.iter().position(|level| *level == base) else {
        return base.to_string();
    };

    if multiplier >= 1.25 {
        index = (index + 1).min(levels.len() - 1);
    } else if multiplier <= 0.85 {
        index = index.saturating_sub(1);
    }

    levels[index].to_string()
}

pub fn adjust_score(base: i64, multiplier: f64) -> i64 {
    ((base as f64) * multiplier).round().clamp(1.0, 100.0) as i64
}

fn matches_environment(value: &str, candidates: &[&str]) -> bool {
    candidates.iter().any(|candidate| value.contains(candidate))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escalates_production_exposed_hosts() {
        let context = HostContext {
            host_id: 1,
            environment: Some("production".to_string()),
            criticality: Some("high".to_string()),
            ssh_open: true,
            os_family: Some("Linux".to_string()),
            os_version: Some("22.04".to_string()),
        };

        assert!(context.context_multiplier() > 1.2);
        assert_eq!(adjust_severity("HIGH", context.context_multiplier()), "CRITICAL");
    }

    #[test]
    fn downgrades_lab_hosts() {
        let context = HostContext {
            host_id: 1,
            environment: Some("lab".to_string()),
            criticality: Some("low".to_string()),
            ssh_open: false,
            os_family: None,
            os_version: None,
        };

        assert!(context.context_multiplier() < 1.0);
        assert_eq!(adjust_severity("HIGH", context.context_multiplier()), "MEDIUM");
    }
}

use crate::models::RiskRecord;
use serde::Serialize;

#[derive(Debug, Serialize)]
struct SarifLog {
    #[serde(rename = "$schema")]
    schema: String,
    version: String,
    runs: Vec<SarifRun>,
}

#[derive(Debug, Serialize)]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
}

#[derive(Debug, Serialize)]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Debug, Serialize)]
struct SarifDriver {
    name: String,
    version: String,
    rules: Vec<SarifRule>,
}

#[derive(Debug, Serialize)]
struct SarifRule {
    id: String,
    name: String,
    short_description: SarifText,
    default_configuration: SarifDefaultConfiguration,
}

#[derive(Debug, Serialize)]
struct SarifText {
    text: String,
}

#[derive(Debug, Serialize)]
struct SarifDefaultConfiguration {
    level: String,
}

#[derive(Debug, Serialize)]
struct SarifResult {
    rule_id: String,
    level: String,
    message: SarifText,
    locations: Vec<SarifLocation>,
}

#[derive(Debug, Serialize)]
struct SarifLocation {
    physical_location: SarifPhysicalLocation,
}

#[derive(Debug, Serialize)]
struct SarifPhysicalLocation {
    artifact_location: SarifArtifactLocation,
}

#[derive(Debug, Serialize)]
struct SarifArtifactLocation {
    uri: String,
}

pub fn export_risks_sarif(risks: &[RiskRecord], version: &str) -> String {
    let mut rules = Vec::new();
    let mut results = Vec::new();
    let mut seen_rules = std::collections::BTreeSet::new();

    for risk in risks {
        if seen_rules.insert(risk.risk_code.clone()) {
            rules.push(SarifRule {
                id: risk.risk_code.clone(),
                name: risk.risk_code.clone(),
                short_description: SarifText {
                    text: risk.title.clone(),
                },
                default_configuration: SarifDefaultConfiguration {
                    level: sarif_level(&risk.severity),
                },
            });
        }

        let target = risk
            .hostname
            .as_deref()
            .or(risk.ip_address.as_deref())
            .unwrap_or("unknown-host");
        results.push(SarifResult {
            rule_id: risk.risk_code.clone(),
            level: sarif_level(&risk.severity),
            message: SarifText {
                text: risk
                    .description
                    .clone()
                    .or(risk.evidence.clone())
                    .unwrap_or_else(|| risk.title.clone()),
            },
            locations: vec![SarifLocation {
                physical_location: SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation {
                        uri: format!("ssh://{target}"),
                    },
                },
            }],
        });
    }

    let document = SarifLog {
        schema: "https://json.schemastore.org/sarif-2.1.0.json".to_string(),
        version: "2.1.0".to_string(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "SSHMap".to_string(),
                    version: version.to_string(),
                    rules,
                },
            },
            results,
        }],
    };

    serde_json::to_string_pretty(&document).unwrap_or_else(|_| "{}".to_string())
}

fn sarif_level(severity: &str) -> String {
    match severity.to_ascii_uppercase().as_str() {
        "CRITICAL" => "error",
        "HIGH" => "error",
        "MEDIUM" => "warning",
        _ => "note",
    }
    .to_string()
}

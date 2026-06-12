use crate::db;
use crate::exceptions;
use crate::models::{AnalysisSummary, AnalyzeScope, NormalizedAnalysis, RawEvidenceForAnalysis};
use crate::parser;
use crate::parser::common::split_file_sections;
use crate::risk::{self, RiskPolicy};
use anyhow::Result;
use std::path::Path;

pub fn run_analysis(
    db_path: &Path,
    scope: AnalyzeScope,
    policy: &RiskPolicy,
    incremental: bool,
) -> Result<AnalysisSummary> {
    if incremental
        && matches!(scope, AnalyzeScope::Graph)
        && let Some(since) = db::get_last_analysis_timestamp(db_path)?
    {
        let new_items = db::count_new_raw_evidence_since(db_path, &since)?;
        if new_items == 0 {
            let stats = db::load_database_stats(db_path)?;
            return Ok(AnalysisSummary {
                skipped: true,
                raw_evidence_items: 0,
                users: 0,
                groups: 0,
                public_keys: 0,
                authorized_keys: 0,
                sshd_config_entries: 0,
                sudo_rules: 0,
                known_hosts_entries: 0,
                ssh_client_config_entries: 0,
                host_aliases: 0,
                risks: stats.risks,
            });
        }
        eprintln!("Incremental analysis: {new_items} new evidence items since last run");
    }

    let raw_evidence = db::load_raw_evidence_for_analysis(db_path)?;
    let analysis = build_normalized_analysis(&raw_evidence);

    let summary = match scope {
        AnalyzeScope::Graph => {
            db::replace_normalized_analysis(db_path, &analysis)?;
            db::update_hostnames_from_evidence(db_path)?;
            db::rebuild_graph_edges(db_path)?;
            db::refresh_data_quality_findings(db_path)?;
            analysis.summary(raw_evidence.len(), db::load_database_stats(db_path)?.risks)
        }
        AnalyzeScope::Risks => {
            let mut risks = risk::generate_risks(&analysis, policy);
            let exceptions = db::list_risk_exceptions(db_path)?;
            risks = exceptions::apply_exceptions(risks, &exceptions);
            let summary = analysis.summary(raw_evidence.len(), risks.len());
            db::replace_risks(db_path, &risks)?;
            summary
        }
        AnalyzeScope::All => {
            let mut risks = risk::generate_risks(&analysis, policy);
            let exceptions = db::list_risk_exceptions(db_path)?;
            risks = exceptions::apply_exceptions(risks, &exceptions);
            let summary = analysis.summary(raw_evidence.len(), risks.len());
            db::replace_normalized_analysis(db_path, &analysis)?;
            db::replace_risks(db_path, &risks)?;
            db::update_hostnames_from_evidence(db_path)?;
            db::rebuild_graph_edges(db_path)?;
            db::refresh_data_quality_findings(db_path)?;
            summary
        }
    };

    db::record_analysis_finished(db_path)?;
    Ok(summary)
}

fn build_normalized_analysis(raw_evidence: &[RawEvidenceForAnalysis]) -> NormalizedAnalysis {
    let mut analysis = NormalizedAnalysis::default();

    for evidence in raw_evidence {
        if evidence.exit_code != Some(0) {
            continue;
        }

        match evidence.evidence_type.as_str() {
            "passwd" => {
                analysis.users.extend(parser::passwd::parse_passwd(
                    &evidence.content,
                    evidence.host_id,
                ));
            }
            "group" => {
                analysis.groups.extend(parser::group::parse_group(
                    &evidence.content,
                    evidence.host_id,
                ));
            }
            "host_metadata" => {
                if let Some(metadata) =
                    parser::host_metadata::parse_host_metadata(&evidence.content, evidence.host_id)
                {
                    analysis.host_metadata.push(metadata);
                }
            }
            "hosts_file" => {
                for section in split_file_sections(
                    &evidence.content,
                    default_source_file(&evidence.source, evidence.evidence_type.as_str()),
                ) {
                    analysis
                        .host_aliases
                        .extend(parser::hosts_file::parse_hosts_file(
                            &section.content,
                            evidence.host_id,
                            &section.source_file,
                        ));
                }
            }
            "sshd_config" => {
                for section in split_file_sections(
                    &evidence.content,
                    default_source_file(&evidence.source, evidence.evidence_type.as_str()),
                ) {
                    analysis
                        .sshd_config_entries
                        .extend(parser::sshd_config::parse_sshd_config(
                            &section.content,
                            evidence.host_id,
                            &section.source_file,
                        ));
                }
            }
            "sshd_effective_config" => {
                analysis.sshd_config_entries.extend(
                    parser::sshd_config::parse_effective_sshd_config(
                        &evidence.content,
                        evidence.host_id,
                        default_source_file(&evidence.source, evidence.evidence_type.as_str()),
                    ),
                );
            }
            "authorized_keys" => {
                for section in split_file_sections(
                    &evidence.content,
                    default_source_file(&evidence.source, evidence.evidence_type.as_str()),
                ) {
                    if let Some(username) =
                        parser::authorized_keys::username_from_authorized_keys_path(
                            &section.source_file,
                        )
                    {
                        analysis.authorized_keys.extend(
                            parser::authorized_keys::parse_authorized_keys(
                                &section.content,
                                evidence.host_id,
                                &username,
                                &section.source_file,
                            ),
                        );
                    }
                }
            }
            "sudoers" => {
                for section in split_file_sections(
                    &evidence.content,
                    default_source_file(&evidence.source, evidence.evidence_type.as_str()),
                ) {
                    analysis.sudo_rules.extend(parser::sudoers::parse_sudoers(
                        &section.content,
                        evidence.host_id,
                        &section.source_file,
                    ));
                }
            }
            "known_hosts" => {
                for section in split_file_sections(
                    &evidence.content,
                    default_source_file(&evidence.source, evidence.evidence_type.as_str()),
                ) {
                    analysis
                        .known_hosts_entries
                        .extend(parser::known_hosts::parse_known_hosts(
                            &section.content,
                            evidence.host_id,
                            &section.source_file,
                        ));
                }
            }
            "ssh_config" => {
                for section in split_file_sections(
                    &evidence.content,
                    default_source_file(&evidence.source, evidence.evidence_type.as_str()),
                ) {
                    analysis.ssh_client_config_entries.extend(
                        parser::ssh_config::parse_ssh_config(
                            &section.content,
                            evidence.host_id,
                            &section.source_file,
                        ),
                    );
                }
            }
            _ => {}
        }
    }

    analysis
}

fn default_source_file(source: &str, evidence_type: &str) -> &'static str {
    match (source, evidence_type) {
        ("sshd_config", _) => "/etc/ssh/sshd_config",
        ("root_authorized_keys", _) => "/root/.ssh/authorized_keys",
        ("sudoers", _) => "/etc/sudoers",
        (_, "passwd") => "getent passwd",
        (_, "group") => "getent group",
        (_, "host_metadata") => "/etc/os-release",
        (_, "hosts_file") => "/etc/hosts",
        (_, "sshd_effective_config") => "sshd -T",
        (_, "sshd_config") => "sshd_config",
        (_, "authorized_keys") => "authorized_keys",
        (_, "sudoers") => "sudoers",
        (_, "known_hosts") => "known_hosts",
        (_, "ssh_config") => "ssh_config",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analyzes_passwd_evidence() {
        let evidence = vec![RawEvidenceForAnalysis {
            host_id: 1,
            evidence_type: "passwd".to_string(),
            source: "passwd".to_string(),
            content: "root:x:0:0:root:/root:/bin/bash".to_string(),
            exit_code: Some(0),
        }];

        let analysis = build_normalized_analysis(&evidence);

        assert_eq!(analysis.users.len(), 1);
        assert_eq!(analysis.users[0].username, "root");
    }

    #[test]
    fn parses_ssh_config_evidence() {
        let evidence = vec![RawEvidenceForAnalysis {
            host_id: 1,
            evidence_type: "ssh_config".to_string(),
            source: "ssh_config".to_string(),
            content: "Host db01\n  ProxyJump bastion\n".to_string(),
            exit_code: Some(0),
        }];

        let analysis = build_normalized_analysis(&evidence);

        assert_eq!(analysis.ssh_client_config_entries.len(), 1);
    }

    #[test]
    fn parses_hosts_file_evidence() {
        let evidence = vec![RawEvidenceForAnalysis {
            host_id: 1,
            evidence_type: "hosts_file".to_string(),
            source: "hosts_file".to_string(),
            content: "10.0.0.10 web01 web01.internal".to_string(),
            exit_code: Some(0),
        }];

        let analysis = build_normalized_analysis(&evidence);

        assert_eq!(analysis.host_aliases.len(), 2);
    }

    #[test]
    fn skips_failed_evidence() {
        let evidence = vec![RawEvidenceForAnalysis {
            host_id: 1,
            evidence_type: "passwd".to_string(),
            source: "passwd".to_string(),
            content: "root:x:0:0:root:/root:/bin/bash".to_string(),
            exit_code: Some(255),
        }];

        let analysis = build_normalized_analysis(&evidence);

        assert!(analysis.users.is_empty());
    }

    #[test]
    fn skips_incremental_analysis_when_no_new_evidence() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let db_path = temp_dir.path().join("incremental.db");
        db::initialize_database(&db_path).expect("initialize database");
        db::record_analysis_finished(&db_path).expect("record analysis finished");

        let summary = run_analysis(&db_path, AnalyzeScope::Graph, &RiskPolicy::default(), true)
            .expect("incremental analysis");

        assert!(summary.skipped);
    }
}

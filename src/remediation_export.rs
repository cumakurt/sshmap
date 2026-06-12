use crate::models::RiskRecord;
use crate::risk::remediation_for_code;
use anyhow::Result;
use std::fmt::Write;

pub enum RemediationExportFormat {
    Ansible,
    Shell,
}

impl RemediationExportFormat {
    pub fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "ansible" => Ok(Self::Ansible),
            "shell" => Ok(Self::Shell),
            other => anyhow::bail!("unsupported remediation export format: {other}"),
        }
    }
}

pub fn export_remediation(risks: &[RiskRecord], format: RemediationExportFormat) -> String {
    match format {
        RemediationExportFormat::Ansible => render_ansible_playbook(risks),
        RemediationExportFormat::Shell => render_shell_script(risks),
    }
}

fn render_ansible_playbook(risks: &[RiskRecord]) -> String {
    let mut output = String::from(
        "---\n- name: SSHMap remediation playbook\n  hosts: all\n  become: true\n  tasks:\n",
    );
    let mut seen = std::collections::BTreeSet::new();

    for risk in risks {
        if !seen.insert(risk.risk_code.clone()) {
            continue;
        }
        let Some(remediation) = remediation_for_code(&risk.risk_code) else {
            continue;
        };
        if let Some(task) = remediation.ansible.as_ref() {
            writeln!(
                output,
                "    - name: {} ({})\n{}\n",
                remediation.title,
                risk.risk_code,
                indent_yaml(task, 6)
            )
            .expect("writing to String cannot fail");
        } else {
            for fix in &remediation.fix {
                writeln!(
                    output,
                    "    - name: {} - {}\n      debug:\n        msg: \"{}\"\n",
                    risk.risk_code,
                    remediation.title,
                    escape_yaml(fix)
                )
                .expect("writing to String cannot fail");
            }
        }
    }

    output
}

fn render_shell_script(risks: &[RiskRecord]) -> String {
    let mut output =
        String::from("#!/bin/sh\n# SSHMap remediation script - review before running\nset -eu\n\n");
    let mut seen = std::collections::BTreeSet::new();

    for risk in risks {
        if !seen.insert(risk.risk_code.clone()) {
            continue;
        }
        let Some(remediation) = remediation_for_code(&risk.risk_code) else {
            continue;
        };
        writeln!(output, "# {} - {}", risk.risk_code, remediation.title)
            .expect("writing to String cannot fail");
        for verify in &remediation.verify {
            writeln!(output, "# verify: {verify}").expect("writing to String cannot fail");
        }
        for fix in &remediation.fix {
            writeln!(output, "# fix: {fix}").expect("writing to String cannot fail");
        }
        output.push('\n');
    }

    output
}

fn indent_yaml(content: &str, spaces: usize) -> String {
    let prefix = " ".repeat(spaces);
    content
        .lines()
        .map(|line| format!("{prefix}{line}"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn escape_yaml(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

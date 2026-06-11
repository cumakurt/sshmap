use crate::models::ParsedUser;

const SERVICE_ACCOUNT_NAMES: &[&str] = &[
    "backup", "deploy", "app", "git", "jenkins", "zabbix", "ansible", "oracle", "postgres",
    "mysql", "nginx", "apache",
];

pub fn parse_passwd(content: &str, host_id: i64) -> Vec<ParsedUser> {
    content
        .lines()
        .filter_map(|line| parse_passwd_line(line, host_id))
        .collect()
}

fn parse_passwd_line(line: &str, host_id: i64) -> Option<ParsedUser> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }

    let fields = trimmed.split(':').collect::<Vec<_>>();
    if fields.len() < 7 || fields[0].is_empty() {
        return None;
    }

    let username = fields[0].to_string();
    let uid = fields[2].parse::<i64>().ok();
    let gid = fields[3].parse::<i64>().ok();
    let home_dir = non_empty_string(fields[5]);
    let shell = non_empty_string(fields[6]);
    let shell_value = shell.as_deref().unwrap_or_default();
    let is_root = uid == Some(0) || username == "root";
    let is_system_account = uid.is_some_and(|value| value < 1000) && !is_root;
    let is_service_account = is_system_account
        || shell_value.contains("nologin")
        || shell_value.ends_with("/false")
        || SERVICE_ACCOUNT_NAMES.contains(&username.as_str());

    Some(ParsedUser {
        host_id,
        username,
        uid,
        gid,
        home_dir,
        shell,
        is_root,
        is_system_account,
        is_service_account,
    })
}

fn non_empty_string(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_passwd_users() {
        let users = parse_passwd(
            "root:x:0:0:root:/root:/bin/bash\ndeploy:x:1001:1001::/home/deploy:/bin/bash",
            7,
        );

        assert_eq!(users.len(), 2);
        assert!(users[0].is_root);
        assert_eq!(users[1].username, "deploy");
    }
}

pub const LONG_ABOUT: &str = "\
Agentless SSH exposure management and access graph CLI.

Developer: Cuma Kurt
Email: cumakurt@gmail.com
LinkedIn: https://www.linkedin.com/in/cuma-kurt-34414917/
GitHub: https://github.com/cumakurt/sshmap

License: GNU General Public License v3.0 or later
";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn developer_metadata_is_documented() {
        assert!(LONG_ABOUT.contains("Cuma Kurt"));
        assert!(LONG_ABOUT.contains("cumakurt@gmail.com"));
        assert!(LONG_ABOUT.contains("linkedin.com/in/cuma-kurt-34414917"));
        assert!(LONG_ABOUT.contains("github.com/cumakurt/sshmap"));
        assert!(LONG_ABOUT.contains("GNU General Public License"));
    }
}

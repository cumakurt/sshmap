pub fn field(value: &str) -> String {
    let value = if starts_with_formula_trigger(value) {
        format!("'{value}")
    } else {
        value.to_string()
    };

    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value
    }
}

fn starts_with_formula_trigger(value: &str) -> bool {
    let trimmed = value.trim_start_matches([' ', '\t', '\r', '\n']);
    matches!(trimmed.chars().next(), Some('=' | '+' | '-' | '@'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_csv_values_when_needed() {
        assert_eq!(field("web,01"), "\"web,01\"");
        assert_eq!(field("web\"01"), "\"web\"\"01\"");
    }

    #[test]
    fn prefixes_spreadsheet_formula_values() {
        assert_eq!(field("=cmd|'/C calc'!A0"), "'=cmd|'/C calc'!A0");
        assert_eq!(field(" +SUM(A1:A2)"), "' +SUM(A1:A2)");
    }
}

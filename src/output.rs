//! Output formatters for sci-fuzz findings.
//!
//! Provides SARIF 2.1, JUnit XML, and Forge reproducer output for CI
//! integration.  All formatters are pure functions that take a slice of
//! [`Finding`]s and return a `String`.

use crate::types::{Finding, Severity, U256};

// ── SARIF 2.1 ──────────────────────────────────────────────────────────────

/// Serialize `findings` to a SARIF 2.1 JSON string.
///
/// The resulting document is compatible with GitHub Code Scanning, GitLab
/// SAST, and any SARIF 2.1.0-aware consumer.
pub fn sarif_from_findings(findings: &[Finding], tool_version: &str) -> String {
    // Deduplicate rule IDs to avoid duplication in the `rules` array.
    let mut seen_ids = std::collections::HashSet::new();
    let rules: Vec<serde_json::Value> = findings
        .iter()
        .filter_map(|f| {
            let id = f.failure_id();
            if seen_ids.insert(id.clone()) {
                Some(serde_json::json!({
                    "id": id,
                    "name": sanitize_sarif_name(&f.title),
                    "shortDescription": { "text": f.title },
                    "fullDescription": { "text": f.description },
                    "defaultConfiguration": {
                        "level": sarif_level(&f.severity)
                    },
                    "properties": {
                        "severity": f.severity.to_string()
                    }
                }))
            } else {
                None
            }
        })
        .collect();

    let results: Vec<serde_json::Value> = findings
        .iter()
        .enumerate()
        .map(|(_i, f)| {
            let mut result = serde_json::json!({
                "ruleId": f.failure_id(),
                "level": sarif_level(&f.severity),
                "message": {
                    "text": f.description
                },
                "locations": [
                    {
                        "logicalLocations": [
                            {
                                "name": format!("{}", f.contract),
                                "kind": "module"
                            }
                        ]
                    }
                ]
            });

            let mut props = serde_json::json!({
                "contract": format!("{}", f.contract),
                "reproducerLength": f.reproducer.len()
            });
            if let Some(profit) = f.exploit_profit {
                props["exploitProfitWei"] = serde_json::json!(profit.to_string());
            }
            result["properties"] = props;
            result
        })
        .collect();

    let sarif = serde_json::json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Documents/CommitteeSpecifications/2.1.0/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "sci-fuzz",
                        "version": tool_version,
                        "informationUri": "https://github.com/your-org/sci-fuzz",
                        "rules": rules
                    }
                },
                "results": results
            }
        ]
    });

    serde_json::to_string_pretty(&sarif).unwrap_or_else(|_| "{}".into())
}

/// Map severity to a SARIF result level.
fn sarif_level(sev: &Severity) -> &'static str {
    match sev {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

/// Convert a finding title to a valid SARIF rule name (alphanumeric + dots).
fn sanitize_sarif_name(title: &str) -> String {
    title
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '_' })
        .collect()
}

// ── JUnit XML ──────────────────────────────────────────────────────────────

/// Serialize `findings` to a JUnit XML string for CI test report ingestion.
///
/// Each finding becomes a failing `<testcase>`. A clean run produces a single
/// passing test case so that CI report parsers always see at least one result.
pub fn junit_from_findings(findings: &[Finding], tool_name: &str, elapsed_secs: f64) -> String {
    let failures = findings.len();
    let tests = if findings.is_empty() { 1 } else { failures };

    let mut xml = String::new();
    xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.push_str(&format!(
        "<testsuites name=\"{}\" tests=\"{}\" failures=\"{}\" time=\"{:.3}\">\n",
        xml_escape(tool_name),
        tests,
        failures,
        elapsed_secs,
    ));
    xml.push_str(&format!(
        "  <testsuite name=\"SecurityScan\" tests=\"{}\" failures=\"{}\" time=\"{:.3}\">\n",
        tests, failures, elapsed_secs,
    ));

    if findings.is_empty() {
        xml.push_str(
            "    <testcase name=\"NoFindingsDetected\" classname=\"sci-fuzz\" time=\"0.000\"/>\n",
        );
    } else {
        for f in findings {
            let class = format!("{}", f.contract);
            let name = xml_escape(&f.title);
            let msg = xml_escape(&f.description);
            let sev = xml_escape(&f.severity.to_string());
            xml.push_str(&format!(
                "    <testcase name=\"{}\" classname=\"{}\">\n",
                name, class,
            ));
            xml.push_str(&format!(
                "      <failure message=\"{}\" type=\"{}\">{}</failure>\n",
                name, sev, msg,
            ));
            xml.push_str("    </testcase>\n");
        }
    }

    xml.push_str("  </testsuite>\n");
    xml.push_str("</testsuites>\n");
    xml
}

/// Escape the five XML predefined entities.
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

// ── Forge Reproducer ───────────────────────────────────────────────────────

/// Generate a Foundry test file that reproduces a finding.
///
/// The returned string is valid Solidity that can be saved as
/// `test/Repro_<slug>.t.sol` and run with `forge test --match-test
/// test_repro_<slug>`.
pub fn forge_reproducer(finding: &Finding) -> String {
    let slug: String = finding
        .title
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '_' })
        .take(40)
        .collect();
    let slug_lower = slug.to_ascii_lowercase();

    let contract_addr = format!("{:#x}", finding.contract);

    let mut calls = String::new();
    for tx in &finding.reproducer {
        let sender = format!("{:#x}", tx.sender);
        let to = tx
            .to
            .map(|a| format!("{:#x}", a))
            .unwrap_or_else(|| "address(0)".into());
        let data = hex::encode(&tx.data);

        calls.push_str(&format!("        vm.prank({sender});\n"));
        if tx.value > U256::ZERO {
            let value = tx.value;
            calls.push_str(&format!(
                "        (bool ok_,) = {to}.call{{value: {value}}}(hex\"{data}\");\n"
            ));
        } else {
            calls.push_str(&format!(
                "        (bool ok_,) = {to}.call(hex\"{data}\");\n"
            ));
        }
        calls.push_str("        (void) ok_; // revert may be expected\n");
    }

    format!(
        r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Auto-generated by sci-fuzz — reproducer for:
//   [{sev}] {title}
//
// {desc}
//
// Run with: forge test --match-test test_repro_{slug_lower} -vvvv

import "forge-std/Test.sol";

contract Repro_{slug} is Test {{
    address constant TARGET = {contract};

    function setUp() external {{
        // Fork or deploy as needed, e.g.:
        // vm.createSelectFork(vm.envString("ETH_RPC_URL"));
    }}

    function test_repro_{slug_lower}() external {{
{calls}
        // ------------------------------------------------------------------
        // Add your assertion here, e.g.:
        //   assertEq(TARGET.balance, 0, "funds drained");
        //   assertTrue(IERC20(TOKEN).balanceOf(address(this)) > 0, "profit");
        // ------------------------------------------------------------------
    }}
}}
"#,
        sev = finding.severity,
        title = finding.title,
        desc = finding.description,
        slug_lower = slug_lower,
        slug = slug,
        contract = contract_addr,
        calls = calls,
    )
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Address, Finding, Severity, Transaction};

    fn sample_finding(sev: Severity) -> Finding {
        Finding {
            severity: sev,
            title: "Test Finding".into(),
            description: "A test finding description.".into(),
            contract: Address::repeat_byte(0x42),
            reproducer: vec![],
            exploit_profit: Some(U256::from(1_000_000_u64)),
        }
    }

    fn finding_with_reproducer() -> Finding {
        Finding {
            severity: Severity::Critical,
            title: "Funds Drained".into(),
            description: "Attacker drains treasury via reentrancy.".into(),
            contract: Address::repeat_byte(0xAA),
            reproducer: vec![
                Transaction {
                    sender: Address::repeat_byte(0x01),
                    to: Some(Address::repeat_byte(0xAA)),
                    data: crate::types::Bytes::from(vec![0xde, 0xad, 0xbe, 0xef]),
                    value: U256::ZERO,
                    gas_limit: 1_000_000,
                },
                Transaction {
                    sender: Address::repeat_byte(0x01),
                    to: Some(Address::repeat_byte(0xAA)),
                    data: crate::types::Bytes::from(vec![0xca, 0xfe, 0xba, 0xbe]),
                    value: U256::from(1_000u64),
                    gas_limit: 1_000_000,
                },
            ],
            exploit_profit: Some(U256::from(5_000_000_u64)),
        }
    }

    // ── SARIF ──────────────────────────────────────────────────────────────

    #[test]
    fn sarif_empty_findings_is_valid_json() {
        let s = sarif_from_findings(&[], "0.1.0-test");
        let v: serde_json::Value = serde_json::from_str(&s).expect("should be valid JSON");
        assert_eq!(v["version"], "2.1.0");
        let results = v["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn sarif_schema_field_present() {
        let s = sarif_from_findings(&[], "0.1.0-test");
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert!(v["$schema"]
            .as_str()
            .unwrap()
            .contains("sarif-schema-2.1.0"));
    }

    #[test]
    fn sarif_includes_findings_and_levels() {
        let findings = vec![
            sample_finding(Severity::Critical),
            sample_finding(Severity::Medium),
        ];
        let s = sarif_from_findings(&findings, "0.1.0-test");
        let v: serde_json::Value = serde_json::from_str(&s).expect("valid JSON");
        let results = v["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0]["level"], "error");
        assert_eq!(results[1]["level"], "warning");
    }

    #[test]
    fn sarif_exploit_profit_propagated() {
        let findings = vec![sample_finding(Severity::High)];
        let s = sarif_from_findings(&findings, "0.1.0-test");
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        let props = &v["runs"][0]["results"][0]["properties"];
        assert!(props["exploitProfitWei"].as_str().is_some());
    }

    // ── JUnit XML ──────────────────────────────────────────────────────────

    #[test]
    fn junit_empty_findings_has_passing_testcase() {
        let s = junit_from_findings(&[], "sci-fuzz", 1.5);
        assert!(s.contains("<testcase name=\"NoFindingsDetected\""));
        assert!(s.contains("failures=\"0\""));
        assert!(!s.contains("<failure"));
    }

    #[test]
    fn junit_findings_become_failures() {
        let findings = vec![sample_finding(Severity::High)];
        let s = junit_from_findings(&findings, "sci-fuzz", 2.0);
        assert!(s.contains("<failure"));
        assert!(s.contains("failures=\"1\""));
        assert!(s.contains("type=\"high\""));
    }

    #[test]
    fn junit_xml_escapes_special_chars() {
        let mut f = sample_finding(Severity::Low);
        f.title = "A <b> & 'c' \"d\"".into();
        let s = junit_from_findings(&[f], "sci-fuzz", 0.1);
        assert!(s.contains("&lt;b&gt;"));
        assert!(s.contains("&amp;"));
        assert!(s.contains("&apos;"));
        assert!(s.contains("&quot;"));
    }

    #[test]
    fn junit_multiple_findings_correct_counts() {
        let findings = vec![
            sample_finding(Severity::Critical),
            sample_finding(Severity::High),
            sample_finding(Severity::Medium),
        ];
        let s = junit_from_findings(&findings, "sci-fuzz", 5.0);
        assert!(s.contains("tests=\"3\""));
        assert!(s.contains("failures=\"3\""));
    }

    // ── Forge Reproducer ───────────────────────────────────────────────────

    #[test]
    fn forge_reproducer_generates_valid_skeleton() {
        let finding = sample_finding(Severity::Critical);
        let s = forge_reproducer(&finding);
        assert!(s.contains("pragma solidity"));
        assert!(s.contains("import \"forge-std/Test.sol\""));
        assert!(s.contains("function test_repro_"));
        assert!(s.contains("contract Repro_"));
    }

    #[test]
    fn forge_reproducer_includes_contract_addr() {
        let finding = sample_finding(Severity::High);
        let s = forge_reproducer(&finding);
        // 0x42 repeated — address starts with 4242
        assert!(s.contains("4242"));
    }

    #[test]
    fn forge_reproducer_emits_prank_calls() {
        let finding = finding_with_reproducer();
        let s = forge_reproducer(&finding);
        assert!(s.contains("vm.prank("));
        // Two transactions → two prank calls
        assert_eq!(s.matches("vm.prank(").count(), 2);
        // Second tx has value → uses call{value:...}
        assert!(s.contains("{value:"));
    }
}

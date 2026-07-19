// sandbox.rs
//
// Sandbox / analysis-evasion detection pass
//
// Malware often checks whether it is running inside an
// automated sandbox or debugger and stays dormant if so.
// This pass looks for the four classic evasion families:
// timing checks, debugger detection, VM/environment
// fingerprinting, and resource/user-interaction checks. It
// correlates suspicious imports with anti-analysis strings
// and reports each detected technique with its evidence and a
// category, plus an overall count used by threat scoring.
//
// Connects to:
//   pass.rs           - AnalysisPass trait, Sealed
//   context.rs        - AnalysisContext (reads imports/strings)
//   passes/imports.rs - ImportResult
//   passes/strings.rs - StringResult
//   types.rs          - Severity, StringCategory

use serde::{Deserialize, Serialize};

use crate::context::AnalysisContext;
use crate::error::EngineError;
use crate::pass::{AnalysisPass, Sealed};
use crate::types::{Severity, StringCategory};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxEvasionResult {
    pub techniques: Vec<EvasionTechnique>,
    pub technique_count: usize,
    pub categories: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvasionTechnique {
    pub name: String,
    pub category: String,
    pub evidence: String,
    pub severity: Severity,
}

struct TechniqueDef {
    name: &'static str,
    category: &'static str,
    apis: &'static [&'static str],
    severity: Severity,
}

const TECHNIQUES: &[TechniqueDef] = &[
    TechniqueDef {
        name: "Timing check",
        category: "timing",
        apis: &[
            "GetTickCount", "GetTickCount64", "QueryPerformanceCounter",
            "timeGetTime", "NtDelayExecution", "rdtsc",
        ],
        severity: Severity::Medium,
    },
    TechniqueDef {
        name: "Debugger detection",
        category: "anti-debug",
        apis: &[
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
            "NtQueryInformationProcess", "OutputDebugString",
            "NtSetInformationThread", "DebugActiveProcess",
        ],
        severity: Severity::High,
    },
    TechniqueDef {
        name: "Resource / configuration check",
        category: "resource",
        apis: &[
            "GetSystemInfo", "GlobalMemoryStatusEx", "GetDiskFreeSpace",
            "GetSystemFirmwareTable",
        ],
        severity: Severity::Low,
    },
    TechniqueDef {
        name: "User-interaction check",
        category: "interaction",
        apis: &[
            "GetCursorPos", "GetLastInputInfo", "GetForegroundWindow",
            "GetAsyncKeyState",
        ],
        severity: Severity::Medium,
    },
];

pub struct SandboxEvasionPass;

impl Sealed for SandboxEvasionPass {}

impl AnalysisPass for SandboxEvasionPass {
    fn name(&self) -> &'static str {
        "sandbox"
    }

    fn dependencies(&self) -> &[&'static str] {
        &["imports", "strings"]
    }

    fn run(&self, ctx: &mut AnalysisContext) -> Result<(), EngineError> {
        ctx.sandbox_result = Some(detect_evasion(ctx));
        Ok(())
    }
}

fn detect_evasion(ctx: &AnalysisContext) -> SandboxEvasionResult {
    let functions: Vec<String> = ctx
        .import_result
        .as_ref()
        .map(|r| r.imports.iter().map(|i| i.function.clone()).collect())
        .unwrap_or_default();

    // VM / environment fingerprinting comes mostly from anti-analysis strings.
    let anti_analysis = ctx.string_result.as_ref().and_then(|r| {
        r.strings
            .iter()
            .find(|s| s.category == StringCategory::AntiAnalysis)
            .map(|s| s.value.clone())
    });

    evaluate(&functions, anti_analysis.as_deref())
}

/// Pure detection core: import function names + an optional anti-analysis
/// string. Kept free of AnalysisContext so it is trivially unit-testable.
fn evaluate(functions: &[String], anti_analysis: Option<&str>) -> SandboxEvasionResult {
    let mut techniques = Vec::new();

    for def in TECHNIQUES {
        if let Some(api) = functions
            .iter()
            .find(|f| def.apis.iter().any(|a| eq_ignore_case_aw(f, a)))
        {
            techniques.push(EvasionTechnique {
                name: def.name.to_string(),
                category: def.category.to_string(),
                evidence: format!("import: {api}"),
                severity: def.severity.clone(),
            });
        }
    }

    if let Some(value) = anti_analysis {
        techniques.push(EvasionTechnique {
            name: "VM / environment fingerprinting".to_string(),
            category: "environment".to_string(),
            evidence: format!("string: {}", truncate(value, 60)),
            severity: Severity::High,
        });
    }

    let mut categories: Vec<String> = techniques.iter().map(|t| t.category.clone()).collect();
    categories.sort();
    categories.dedup();

    SandboxEvasionResult {
        technique_count: techniques.len(),
        categories,
        techniques,
    }
}

fn eq_ignore_case_aw(import_name: &str, api: &str) -> bool {
    let lower = import_name.to_lowercase();
    let api_lower = api.to_lowercase();
    lower == api_lower || matches!(lower.strip_prefix(&api_lower), Some("a") | Some("w"))
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        s.chars().take(max).collect::<String>() + "..."
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn funcs(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn detects_debugger_and_timing() {
        let result = evaluate(
            &funcs(&["IsDebuggerPresent", "GetTickCount", "printf"]),
            None,
        );
        assert_eq!(result.technique_count, 2);
        assert!(result.categories.contains(&"anti-debug".to_string()));
        assert!(result.categories.contains(&"timing".to_string()));
    }

    #[test]
    fn handles_aw_suffix() {
        let result = evaluate(&funcs(&["OutputDebugStringW"]), None);
        assert_eq!(result.technique_count, 1);
        assert_eq!(result.techniques[0].category, "anti-debug");
    }

    #[test]
    fn anti_analysis_string_is_environment_technique() {
        let result = evaluate(&funcs(&["printf"]), Some("VMwareServiceHelper"));
        assert_eq!(result.technique_count, 1);
        assert_eq!(result.techniques[0].category, "environment");
        assert_eq!(result.techniques[0].severity, Severity::High);
    }

    #[test]
    fn benign_binary_has_no_techniques() {
        let result = evaluate(&funcs(&["printf", "malloc", "free"]), None);
        assert_eq!(result.technique_count, 0);
        assert!(result.categories.is_empty());
    }
}

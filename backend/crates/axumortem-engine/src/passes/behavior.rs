// behavior.rs
//
// Behavioral pattern detection pass
//
// Correlates findings from the imports, strings, and entropy
// passes into high-level behavioral verdicts (ransomware,
// reverse shell, dropper, keylogger, rootkit). Individual
// indicators (one API, one string) are noisy; a pattern only
// fires when at least three independent indicators agree,
// which keeps false positives low. Each fired pattern carries
// a confidence score, the concrete indicators that matched,
// and the associated MITRE technique IDs.
//
// Connects to:
//   pass.rs           - AnalysisPass trait, Sealed
//   context.rs        - AnalysisContext (reads imports/strings/entropy)
//   passes/imports.rs - ImportResult
//   passes/strings.rs - StringResult
//   passes/entropy.rs - EntropyResult
//   types.rs          - Severity, StringCategory

use serde::{Deserialize, Serialize};

use crate::context::AnalysisContext;
use crate::error::EngineError;
use crate::pass::{AnalysisPass, Sealed};
use crate::types::{Severity, StringCategory};

const MIN_INDICATORS: usize = 3;
const HIGH_ENTROPY_THRESHOLD: f64 = 7.0;
const DROPPER_MAX_IMPORTS: usize = 25;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorResult {
    pub patterns: Vec<BehaviorPattern>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorPattern {
    pub name: String,
    pub category: String,
    pub description: String,
    pub severity: Severity,
    pub confidence: f64,
    pub indicators: Vec<String>,
    pub mitre_ids: Vec<String>,
}

pub struct BehaviorPass;

impl Sealed for BehaviorPass {}

impl AnalysisPass for BehaviorPass {
    fn name(&self) -> &'static str {
        "behavior"
    }

    fn dependencies(&self) -> &[&'static str] {
        &["imports", "strings", "entropy"]
    }

    fn run(&self, ctx: &mut AnalysisContext) -> Result<(), EngineError> {
        let signals = Signals::from_context(ctx);
        ctx.behavior_result = Some(BehaviorResult {
            patterns: signals.detect_patterns(),
        });
        Ok(())
    }
}

/// Pre-computed views over the earlier pass results, cheap to query.
struct Signals {
    functions: Vec<String>,     // import function names (original case)
    string_values: Vec<String>, // lowercased string values
    categories: Vec<StringCategory>,
    high_entropy: bool,
    import_count: usize,
}

impl Signals {
    fn from_context(ctx: &AnalysisContext) -> Self {
        let functions: Vec<String> = ctx
            .import_result
            .as_ref()
            .map(|r| r.imports.iter().map(|i| i.function.clone()).collect())
            .unwrap_or_default();
        let import_count = functions.len();

        let (string_values, categories): (Vec<String>, Vec<StringCategory>) = ctx
            .string_result
            .as_ref()
            .map(|r| {
                (
                    r.strings.iter().map(|s| s.value.to_lowercase()).collect(),
                    r.strings.iter().map(|s| s.category.clone()).collect(),
                )
            })
            .unwrap_or_default();

        let high_entropy = ctx
            .entropy_result
            .as_ref()
            .map(|e| e.packing_detected || e.overall_entropy >= HIGH_ENTROPY_THRESHOLD)
            .unwrap_or(false);

        Self {
            functions,
            string_values,
            categories,
            high_entropy,
            import_count,
        }
    }

    /// Return the first import that matches any of `apis` (case-insensitive,
    /// allowing a Windows A/W suffix).
    fn imports_any(&self, apis: &[&str]) -> Option<String> {
        self.functions
            .iter()
            .find(|f| apis.iter().any(|api| api_matches(f, api)))
            .cloned()
    }

    /// Return the first string value containing any of `needles`.
    fn string_contains_any(&self, needles: &[&str]) -> Option<String> {
        self.string_values
            .iter()
            .find(|v| needles.iter().any(|n| v.contains(n)))
            .cloned()
    }

    fn has_category(&self, cat: StringCategory) -> bool {
        self.categories.iter().any(|c| *c == cat)
    }

    fn detect_patterns(&self) -> Vec<BehaviorPattern> {
        [
            self.ransomware(),
            self.reverse_shell(),
            self.dropper(),
            self.keylogger(),
            self.rootkit(),
        ]
        .into_iter()
        .flatten()
        .collect()
    }

    fn ransomware(&self) -> Option<BehaviorPattern> {
        let mut ind = Vec::new();
        if let Some(m) = self.imports_any(&[
            "CryptEncrypt", "CryptDeriveKey", "CryptGenKey", "BCryptEncrypt",
            "EVP_EncryptInit", "EVP_EncryptInit_ex", "AES_encrypt", "AES_set_encrypt_key",
        ]) {
            ind.push(format!("encryption API: {m}"));
        }
        if let Some(m) = self.imports_any(&[
            "FindFirstFile", "FindNextFile", "readdir", "opendir", "nftw",
        ]) {
            ind.push(format!("file enumeration: {m}"));
        }
        if let Some(m) = self.string_contains_any(&[
            "your files have been encrypted", "ransom", ".locked",
            "decrypt your files", "bitcoin", "recover your files", "readme.txt",
        ]) {
            ind.push(format!("ransom note string: {m}"));
        }
        if self.high_entropy {
            ind.push("high-entropy / packed payload".to_string());
        }
        build_pattern(
            "Ransomware",
            "file-encryption",
            "Encrypts victim files: crypto APIs + file enumeration + ransom \
             note strings + high entropy",
            Severity::Critical,
            &["T1486", "T1083"],
            ind,
            4,
        )
    }

    fn reverse_shell(&self) -> Option<BehaviorPattern> {
        let mut ind = Vec::new();
        if let Some(m) = self.imports_any(&[
            "socket", "connect", "WSASocket", "WSAConnect", "inet_pton", "inet_addr",
        ]) {
            ind.push(format!("socket API: {m}"));
        }
        if let Some(m) = self.imports_any(&[
            "execve", "system", "CreateProcess", "ShellExecute", "WinExec",
            "posix_spawn", "popen",
        ]) {
            ind.push(format!("command execution: {m}"));
        }
        if self.has_category(StringCategory::ShellCommand)
            || self
                .string_contains_any(&["/bin/sh", "/bin/bash", "cmd.exe"])
                .is_some()
        {
            ind.push("shell command string".to_string());
        }
        if let Some(m) = self.imports_any(&["dup2", "dup3"]) {
            ind.push(format!("fd redirection: {m}"));
        }
        build_pattern(
            "Reverse Shell",
            "remote-access",
            "Connects out and pipes a shell: socket + command execution + \
             shell strings + fd redirection",
            Severity::Critical,
            &["T1059", "T1071"],
            ind,
            4,
        )
    }

    fn dropper(&self) -> Option<BehaviorPattern> {
        let mut ind = Vec::new();
        if self.imports_any(&["URLDownloadToFile", "InternetOpen", "WinHttpOpen", "curl_easy_init"]).is_some()
            || self.has_category(StringCategory::Url)
            || self.string_contains_any(&["wget ", "curl ", "http://", "https://"]).is_some()
        {
            ind.push("download capability".to_string());
        }
        if self.imports_any(&["WriteFile", "fwrite", "CreateFile", "fopen", "open"]).is_some() {
            ind.push("writes files to disk".to_string());
        }
        if self.imports_any(&["ShellExecute", "WinExec", "system", "CreateProcess", "execve"]).is_some() {
            ind.push("executes payload".to_string());
        }
        if self.high_entropy {
            ind.push("embedded high-entropy payload".to_string());
        }
        if self.import_count > 0 && self.import_count < DROPPER_MAX_IMPORTS {
            ind.push(format!("minimal imports ({})", self.import_count));
        }
        build_pattern(
            "Dropper",
            "delivery",
            "Downloads/writes and executes a second-stage payload",
            Severity::High,
            &["T1105"],
            ind,
            5,
        )
    }

    fn keylogger(&self) -> Option<BehaviorPattern> {
        let mut ind = Vec::new();
        if let Some(m) = self.imports_any(&[
            "SetWindowsHookEx", "GetAsyncKeyState", "GetKeyState",
            "GetKeyboardState", "RegisterRawInputDevices", "GetRawInputData",
        ]) {
            ind.push(format!("keyboard capture: {m}"));
        }
        if self.imports_any(&["WriteFile", "fwrite", "fopen", "CreateFile"]).is_some() {
            ind.push("logs to a file".to_string());
        }
        if self.imports_any(&["RegSetValueEx", "CreateService"]).is_some()
            || self.has_category(StringCategory::PersistencePath)
        {
            ind.push("persistence mechanism".to_string());
        }
        if self.imports_any(&["send", "InternetOpen", "socket", "WSASend"]).is_some() {
            ind.push("network exfiltration".to_string());
        }
        build_pattern(
            "Keylogger",
            "collection",
            "Captures keystrokes, logs them, and persists",
            Severity::High,
            &["T1056.001"],
            ind,
            4,
        )
    }

    fn rootkit(&self) -> Option<BehaviorPattern> {
        let mut ind = Vec::new();
        if let Some(m) = self.imports_any(&["ptrace", "process_vm_writev", "process_vm_readv"]) {
            ind.push(format!("process manipulation: {m}"));
        }
        if let Some(m) = self.string_contains_any(&[
            "insmod", "init_module", "/dev/kmem", "/dev/mem", "kernel module",
            "/proc/modules", "rmmod",
        ]) {
            ind.push(format!("kernel module string: {m}"));
        }
        if let Some(m) = self.string_contains_any(&["/tmp/.", "/dev/shm/", "ld_preload", "/.hidden"]) {
            ind.push(format!("hiding artifact: {m}"));
        }
        if self.imports_any(&["dlopen", "dlsym"]).is_some() {
            ind.push("runtime symbol resolution".to_string());
        }
        build_pattern(
            "Rootkit",
            "defense-evasion",
            "Manipulates the kernel/processes and hides its presence",
            Severity::Critical,
            &["T1014", "T1055.008"],
            ind,
            4,
        )
    }
}

/// Match an import name against an API name (case-insensitive, allowing a
/// trailing Windows `A`/`W` variant), avoiding substring false positives.
fn api_matches(import_name: &str, api: &str) -> bool {
    let lower = import_name.to_lowercase();
    let api_lower = api.to_lowercase();
    if lower == api_lower {
        return true;
    }
    matches!(lower.strip_prefix(&api_lower), Some("a") | Some("w"))
}

#[allow(clippy::too_many_arguments)]
fn build_pattern(
    name: &str,
    category: &str,
    description: &str,
    severity: Severity,
    mitre_ids: &[&str],
    indicators: Vec<String>,
    total_candidates: usize,
) -> Option<BehaviorPattern> {
    if indicators.len() < MIN_INDICATORS {
        return None;
    }
    let confidence = (indicators.len() as f64 / total_candidates as f64).min(1.0);
    Some(BehaviorPattern {
        name: name.to_string(),
        category: category.to_string(),
        description: description.to_string(),
        severity,
        confidence: (confidence * 100.0).round() / 100.0,
        indicators,
        mitre_ids: mitre_ids.iter().map(|s| s.to_string()).collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signals(
        functions: &[&str],
        strings: &[&str],
        categories: &[StringCategory],
        high_entropy: bool,
    ) -> Signals {
        Signals {
            functions: functions.iter().map(|s| s.to_string()).collect(),
            string_values: strings.iter().map(|s| s.to_lowercase()).collect(),
            categories: categories.to_vec(),
            high_entropy,
            import_count: functions.len(),
        }
    }

    fn find<'a>(patterns: &'a [BehaviorPattern], name: &str) -> Option<&'a BehaviorPattern> {
        patterns.iter().find(|p| p.name == name)
    }

    #[test]
    fn detects_reverse_shell() {
        let s = signals(
            &["socket", "execve", "dup2"],
            &[],
            &[StringCategory::ShellCommand],
            false,
        );
        let patterns = s.detect_patterns();
        let rs = find(&patterns, "Reverse Shell").expect("reverse shell should fire");
        assert_eq!(rs.severity, Severity::Critical);
        assert!(rs.indicators.len() >= MIN_INDICATORS);
        assert!(rs.confidence > 0.0 && rs.confidence <= 1.0);
        assert!(rs.mitre_ids.contains(&"T1059".to_string()));
    }

    #[test]
    fn detects_ransomware() {
        let s = signals(
            &["CryptEncrypt", "FindFirstFileW"],
            &["Your files have been encrypted"],
            &[],
            true,
        );
        let patterns = s.detect_patterns();
        let rw = find(&patterns, "Ransomware").expect("ransomware should fire");
        assert_eq!(rw.severity, Severity::Critical);
        assert_eq!(rw.indicators.len(), 4);
    }

    #[test]
    fn detects_dropper() {
        let s = signals(
            &["URLDownloadToFileW", "WriteFile", "ShellExecuteA"],
            &[],
            &[],
            false,
        );
        let patterns = s.detect_patterns();
        assert!(find(&patterns, "Dropper").is_some());
    }

    #[test]
    fn benign_binary_fires_nothing() {
        let s = signals(&["printf", "malloc", "free", "puts"], &["hello world"], &[], false);
        assert!(s.detect_patterns().is_empty());
    }

    #[test]
    fn two_indicators_do_not_fire() {
        // socket + execve only (2 indicators) - below the min-3 threshold
        let s = signals(&["socket", "execve"], &[], &[], false);
        assert!(find(&s.detect_patterns(), "Reverse Shell").is_none());
    }

    #[test]
    fn api_matching_ignores_case_and_aw_suffix() {
        assert!(api_matches("IsDebuggerPresent", "isdebuggerpresent"));
        assert!(api_matches("RegSetValueExW", "RegSetValueEx"));
        assert!(!api_matches("reconnect", "connect"));
    }
}

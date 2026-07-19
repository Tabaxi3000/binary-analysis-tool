// mod.rs
//
// Binary format parsing dispatcher and shared format types
//
// Dispatches binary data to the appropriate format parser
// (ELF, PE, or Mach-O) via goblin::Object::parse and
// returns a unified FormatResult. Defines all shared format
// types: SectionInfo and SegmentInfo with permissions and
// SHA-256 hashes, FormatAnomaly enum (entry point outside
// text, RWX sections, suspicious section names, empty names,
// virtual/raw size mismatches, overlay data, TLS callbacks,
// missing import tables, suspicious timestamps),
// format-specific info structs (PeInfo with DLL
// characteristics, ElfInfo with RELRO/BIND_NOW/stack
// executable flags, MachOInfo with code signature and dylib
// list). SUSPICIOUS_SECTION_NAMES maps 15 packer section
// names to their tool names. detect_common_anomalies runs
// cross-format structural checks on entry point placement,
// RWX permissions, section naming, and size ratios.
//
// Connects to:
//   formats/elf.rs   - parse_elf
//   formats/pe.rs    - parse_pe
//   formats/macho.rs - parse_macho
//   types.rs         - Architecture, BinaryFormat, Endianness,
//                       SectionPermissions
//   error.rs         - EngineError

mod elf;
mod macho;
mod pe;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::EngineError;
use crate::types::{Architecture, BinaryFormat, Endianness, SectionPermissions};

pub const SUSPICIOUS_SECTION_NAMES: &[(&str, &str)] = &[
    ("UPX0", "UPX packer"),
    ("UPX1", "UPX packer"),
    ("UPX2", "UPX packer"),
    (".nsp0", "NSPack"),
    (".nsp1", "NSPack"),
    (".nsp2", "NSPack"),
    (".aspack", "ASPack"),
    (".adata", "ASPack"),
    (".MPress1", "MPress"),
    (".MPress2", "MPress"),
    (".themida", "Themida"),
    (".vmp0", "VMProtect"),
    (".vmp1", "VMProtect"),
    (".enigma1", "Enigma"),
    (".enigma2", "Enigma"),
];

const VIRTUAL_RAW_RATIO_THRESHOLD: f64 = 10.0;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormatResult {
    pub format: BinaryFormat,
    pub architecture: Architecture,
    pub bits: u8,
    pub endianness: Endianness,
    pub entry_point: u64,
    pub is_stripped: bool,
    pub is_pie: bool,
    pub has_debug_info: bool,
    pub sections: Vec<SectionInfo>,
    pub segments: Vec<SegmentInfo>,
    pub anomalies: Vec<FormatAnomaly>,
    pub pe_info: Option<PeInfo>,
    pub elf_info: Option<ElfInfo>,
    pub macho_info: Option<MachOInfo>,
    #[serde(default)]
    pub function_hints: Vec<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionInfo {
    pub name: String,
    pub virtual_address: u64,
    pub virtual_size: u64,
    pub raw_offset: u64,
    pub raw_size: u64,
    pub permissions: SectionPermissions,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SegmentInfo {
    pub name: Option<String>,
    pub virtual_address: u64,
    pub virtual_size: u64,
    pub file_offset: u64,
    pub file_size: u64,
    pub permissions: SectionPermissions,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FormatAnomaly {
    EntryPointOutsideText {
        ep: u64,
        text_range: (u64, u64),
    },
    EntryPointInLastSection {
        ep: u64,
        section: String,
    },
    EntryPointOutsideSections {
        ep: u64,
    },
    RwxSection {
        name: String,
    },
    EmptySectionName {
        index: usize,
    },
    StrippedBinary,
    SuspiciousSectionName {
        name: String,
        reason: String,
    },
    ZeroSizeCodeSection {
        name: String,
    },
    VirtualRawSizeMismatch {
        name: String,
        virtual_size: u64,
        raw_size: u64,
        ratio: f64,
    },
    OverlayData {
        offset: u64,
        size: u64,
    },
    TlsCallbacksPresent {
        count: usize,
    },
    NoImportTable,
    SuspiciousTimestamp {
        value: u32,
        reason: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeInfo {
    pub image_base: u64,
    pub subsystem: String,
    pub dll_characteristics: PeDllCharacteristics,
    pub timestamp: u32,
    pub linker_version: String,
    pub tls_callback_count: usize,
    pub has_overlay: bool,
    pub overlay_size: u64,
    pub rich_header_present: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeDllCharacteristics {
    pub aslr: bool,
    pub dep: bool,
    pub cfg: bool,
    pub no_seh: bool,
    pub force_integrity: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElfInfo {
    pub os_abi: String,
    pub elf_type: String,
    pub interpreter: Option<String>,
    pub gnu_relro: bool,
    pub bind_now: bool,
    pub stack_executable: bool,
    pub needed_libraries: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachOInfo {
    pub file_type: String,
    pub cpu_subtype: String,
    pub is_universal: bool,
    pub has_code_signature: bool,
    pub min_os_version: Option<String>,
    pub sdk_version: Option<String>,
    pub dylibs: Vec<String>,
    pub has_function_starts: bool,
}

/// A recognized non-executable file type, used to produce a helpful error
/// instead of a generic parse failure.
pub struct NonExecutableType {
    pub name: &'static str,
    pub guidance: &'static str,
}

const NEED_EXECUTABLE: &str = "Binary analysis requires an executable (ELF, PE, or Mach-O).";

/// Detect common non-executable container/document formats by magic bytes.
///
/// Runs before the goblin parse so users who upload a PDF or ZIP get a clear
/// explanation. The Java-class / Mach-O universal collision (both start with
/// `0xCAFEBABE`) is deliberately NOT checked here so real Mach-O fat binaries
/// still reach the parser.
pub fn detect_non_executable(data: &[u8]) -> Option<NonExecutableType> {
    const SIGNATURES: &[(&[u8], NonExecutableType)] = &[
        (b"%PDF", NonExecutableType {
            name: "PDF",
            guidance: NEED_EXECUTABLE,
        }),
        (b"PK\x03\x04", NonExecutableType {
            name: "ZIP/Office (DOCX, XLSX, JAR)",
            guidance: "This is a ZIP-based archive. Office macros and embedded \
                       objects can be extracted and analyzed as separate targets.",
        }),
        (b"\x1f\x8b", NonExecutableType {
            name: "GZIP",
            guidance: "Decompress the archive first, then analyze the contents.",
        }),
        (b"Rar!\x1a\x07", NonExecutableType {
            name: "RAR",
            guidance: "Extract the archive first, then analyze the contents.",
        }),
        (b"7z\xbc\xaf\x27\x1c", NonExecutableType {
            name: "7-Zip",
            guidance: "Extract the archive first, then analyze the contents.",
        }),
        (b"\x89PNG", NonExecutableType {
            name: "PNG image",
            guidance: "Images are not executables.",
        }),
        (b"\xff\xd8\xff", NonExecutableType {
            name: "JPEG image",
            guidance: "Images are not executables.",
        }),
        (b"GIF8", NonExecutableType {
            name: "GIF image",
            guidance: "Images are not executables.",
        }),
        (b"%!PS", NonExecutableType {
            name: "PostScript",
            guidance: NEED_EXECUTABLE,
        }),
    ];

    SIGNATURES
        .iter()
        .find(|(magic, _)| data.starts_with(magic))
        .map(|(_, ft)| NonExecutableType {
            name: ft.name,
            guidance: ft.guidance,
        })
}

pub fn parse_format(data: &[u8]) -> Result<FormatResult, EngineError> {
    if let Some(file_type) = detect_non_executable(data) {
        return Err(EngineError::UnsupportedFileType {
            detected: file_type.name.to_string(),
            guidance: file_type.guidance.to_string(),
        });
    }

    let object = goblin::Object::parse(data).map_err(|e| EngineError::InvalidBinary {
        reason: e.to_string(),
    })?;

    match &object {
        goblin::Object::Elf(elf_obj) => elf::parse_elf(elf_obj, data),
        goblin::Object::PE(pe_obj) => pe::parse_pe(pe_obj, data),
        goblin::Object::Mach(mach_obj) => macho::parse_macho(mach_obj, data),
        _ => Err(EngineError::UnsupportedFormat {
            format: "unknown".into(),
        }),
    }
}

fn compute_section_hash(data: &[u8], offset: u64, size: u64) -> String {
    if size == 0 {
        return String::new();
    }
    let start = offset as usize;
    let end = start.saturating_add(size as usize);
    if start >= data.len() || end > data.len() {
        return String::new();
    }
    let hash = Sha256::digest(&data[start..end]);
    format!("{hash:x}")
}

fn check_suspicious_name(name: &str) -> Option<String> {
    for &(suspicious, reason) in SUSPICIOUS_SECTION_NAMES {
        if name == suspicious {
            return Some(reason.into());
        }
    }
    None
}

fn detect_common_anomalies(
    sections: &[SectionInfo],
    entry_point: u64,
    is_stripped: bool,
) -> Vec<FormatAnomaly> {
    let mut anomalies = Vec::new();

    let text_section = sections.iter().find(|s| s.name == ".text");
    if let Some(text) = text_section {
        let text_end = text.virtual_address + text.virtual_size;
        if entry_point != 0 && (entry_point < text.virtual_address || entry_point >= text_end) {
            anomalies.push(FormatAnomaly::EntryPointOutsideText {
                ep: entry_point,
                text_range: (text.virtual_address, text_end),
            });
        }
    }

    if let Some(last) = sections.last() {
        let last_end = last.virtual_address + last.virtual_size;
        if entry_point >= last.virtual_address && entry_point < last_end {
            anomalies.push(FormatAnomaly::EntryPointInLastSection {
                ep: entry_point,
                section: last.name.clone(),
            });
        }
    }

    let ep_in_any = sections.iter().any(|s| {
        entry_point >= s.virtual_address && entry_point < s.virtual_address + s.virtual_size
    });
    if !ep_in_any && entry_point != 0 {
        anomalies.push(FormatAnomaly::EntryPointOutsideSections { ep: entry_point });
    }

    for (idx, section) in sections.iter().enumerate() {
        if section.permissions.is_rwx() {
            anomalies.push(FormatAnomaly::RwxSection {
                name: section.name.clone(),
            });
        }

        if section.name.is_empty() {
            anomalies.push(FormatAnomaly::EmptySectionName { index: idx });
        }

        if let Some(reason) = check_suspicious_name(&section.name) {
            anomalies.push(FormatAnomaly::SuspiciousSectionName {
                name: section.name.clone(),
                reason,
            });
        }

        if section.permissions.execute && section.virtual_size == 0 {
            anomalies.push(FormatAnomaly::ZeroSizeCodeSection {
                name: section.name.clone(),
            });
        }

        if section.raw_size > 0 {
            let ratio = section.virtual_size as f64 / section.raw_size as f64;
            if ratio > VIRTUAL_RAW_RATIO_THRESHOLD {
                anomalies.push(FormatAnomaly::VirtualRawSizeMismatch {
                    name: section.name.clone(),
                    virtual_size: section.virtual_size,
                    raw_size: section.raw_size,
                    ratio,
                });
            }
        }
    }

    if is_stripped {
        anomalies.push(FormatAnomaly::StrippedBinary);
    }

    anomalies
}

#[cfg(test)]
mod file_type_tests {
    use super::*;

    #[test]
    fn detects_common_non_executables() {
        assert_eq!(detect_non_executable(b"%PDF-1.7\n...").unwrap().name, "PDF");
        assert_eq!(
            detect_non_executable(b"PK\x03\x04rest").unwrap().name,
            "ZIP/Office (DOCX, XLSX, JAR)"
        );
        assert_eq!(detect_non_executable(b"\x1f\x8b\x08").unwrap().name, "GZIP");
        assert_eq!(detect_non_executable(b"\x89PNG\r\n").unwrap().name, "PNG image");
    }

    #[test]
    fn does_not_flag_executables_or_unknowns() {
        // ELF magic, PE magic, and a Mach-O universal (0xCAFEBABE) must pass through
        assert!(detect_non_executable(b"\x7fELF\x02\x01\x01").is_none());
        assert!(detect_non_executable(b"MZ\x90\x00").is_none());
        assert!(detect_non_executable(b"\xca\xfe\xba\xbe").is_none());
        assert!(detect_non_executable(b"random bytes here").is_none());
    }

    #[test]
    fn parse_format_returns_helpful_error_for_pdf() {
        let err = parse_format(b"%PDF-1.7 fake pdf content").unwrap_err();
        match err {
            EngineError::UnsupportedFileType { detected, guidance } => {
                assert_eq!(detected, "PDF");
                assert!(guidance.contains("executable"));
            }
            other => panic!("expected UnsupportedFileType, got {other:?}"),
        }
    }
}

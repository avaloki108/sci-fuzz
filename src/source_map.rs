//! Source map ingestion and PC-to-source-line mapping.
//!
//! Solidity (and Foundry/solc) emits a source map for each contract's deployed
//! bytecode.  The format is a semicolon-separated list of entries, one per
//! EVM instruction:
//!
//!   `s:l:f:j:m;s:l:f:j:m;...`
//!
//! Fields may be omitted (inherit from the previous entry):
//!
//!   `0:10:0:-:0;:3::;5::1;...`
//!
//! Fields:
//! - `s` — byte offset into the source file
//! - `l` — length in bytes of the source span
//! - `f` — file index in the compilation unit's source file list
//! - `j` — jump type (`i` = jump into function, `o` = jump out, `-` = none)
//! - `m` — modifier depth (unused here)
//!
//! We parse this into a `Vec<SourceEntry>` aligned with the instruction list.
//! To map a PC to an entry, we first convert the bytecode into a
//! `pc_to_instruction_index` table (each byte in the bytecode is either the
//! start of an instruction or part of PUSH data).

use std::collections::HashMap;

use crate::types::Address;

// ---------------------------------------------------------------------------
// Source entry
// ---------------------------------------------------------------------------

/// One entry in a Solidity source map — maps one EVM instruction to a source
/// span.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceEntry {
    /// Byte offset in the source file (-1 means "generated code / no mapping").
    pub start: i64,
    /// Byte length of the span (0 means point location).
    pub length: i64,
    /// Index into the compilation unit's source file list (-1 = generated).
    pub file_index: i32,
    /// Jump type: `i` = into, `o` = out, `-` = none.
    pub jump: char,
}

impl Default for SourceEntry {
    fn default() -> Self {
        Self {
            start: -1,
            length: 0,
            file_index: -1,
            jump: '-',
        }
    }
}

// ---------------------------------------------------------------------------
// Source map parser
// ---------------------------------------------------------------------------

/// Parse a Solidity source map string into a `Vec<SourceEntry>`.
///
/// Returns one entry per EVM instruction.  Returns an empty `Vec` if the
/// input is empty or unparseable.
pub fn parse_source_map(source_map: &str) -> Vec<SourceEntry> {
    if source_map.is_empty() {
        return Vec::new();
    }

    let mut entries: Vec<SourceEntry> = Vec::new();
    let mut prev = SourceEntry::default();

    for segment in source_map.split(';') {
        let mut entry = prev.clone();

        let parts: Vec<&str> = segment.split(':').collect();

        // Field 0: start
        if let Some(&s) = parts.first() {
            if !s.is_empty() {
                if let Ok(v) = s.parse::<i64>() {
                    entry.start = v;
                }
            }
        }
        // Field 1: length
        if let Some(&l) = parts.get(1) {
            if !l.is_empty() {
                if let Ok(v) = l.parse::<i64>() {
                    entry.length = v;
                }
            }
        }
        // Field 2: file index
        if let Some(&f) = parts.get(2) {
            if !f.is_empty() {
                if let Ok(v) = f.parse::<i32>() {
                    entry.file_index = v;
                }
            }
        }
        // Field 3: jump type
        if let Some(&j) = parts.get(3) {
            if !j.is_empty() {
                entry.jump = j.chars().next().unwrap_or('-');
            }
        }

        prev = entry.clone();
        entries.push(entry);
    }

    entries
}

// ---------------------------------------------------------------------------
// PC → instruction index table
// ---------------------------------------------------------------------------

/// Build a table mapping each PC (byte offset in bytecode) to its
/// instruction index (0-based count of opcodes).
///
/// For PUSH opcodes (0x60–0x7f), subsequent bytes are data — they are not
/// instructions and do not appear in the source map.
pub fn build_pc_to_instruction_index(bytecode: &[u8]) -> Vec<Option<usize>> {
    let mut table = vec![None; bytecode.len()];
    let mut pc = 0usize;
    let mut instr_idx = 0usize;

    while pc < bytecode.len() {
        table[pc] = Some(instr_idx);
        let opcode = bytecode[pc];
        // PUSH1 = 0x60 … PUSH32 = 0x7f
        let push_size = if (0x60..=0x7f).contains(&opcode) {
            (opcode - 0x5f) as usize
        } else {
            0
        };
        pc += 1 + push_size;
        instr_idx += 1;
    }

    table
}

// ---------------------------------------------------------------------------
// BytecodeSourceMap — the main artifact
// ---------------------------------------------------------------------------

/// Associates a deployed contract's bytecode with its Solidity source map.
///
/// Provides fast PC → `SourceEntry` lookups.
#[derive(Debug, Clone)]
pub struct BytecodeSourceMap {
    entries: Vec<SourceEntry>,
    pc_to_instr: Vec<Option<usize>>,
}

impl BytecodeSourceMap {
    /// Build from raw bytecode bytes and a source map string.
    pub fn new(bytecode: &[u8], source_map: &str) -> Self {
        let entries = parse_source_map(source_map);
        let pc_to_instr = build_pc_to_instruction_index(bytecode);
        Self {
            entries,
            pc_to_instr,
        }
    }

    /// Look up the source entry for a given PC.
    ///
    /// Returns `None` if the PC is out of range, points to PUSH data, or has
    /// no corresponding source map entry.
    pub fn entry_for_pc(&self, pc: usize) -> Option<&SourceEntry> {
        let instr_idx = self.pc_to_instr.get(pc)?.as_ref()?;
        self.entries.get(*instr_idx)
    }

    /// Iterate over all instructions with their source entries.
    pub fn iter(&self) -> impl Iterator<Item = (usize, &SourceEntry)> {
        self.entries.iter().enumerate()
    }

    /// Number of instructions in the source map.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True if empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Source coverage: PC hits → covered lines
// ---------------------------------------------------------------------------

/// Coverage data for a single source file.
#[derive(Debug, Clone, Default)]
pub struct FileCoverage {
    /// 1-based line numbers that were executed.
    pub covered_lines: std::collections::BTreeSet<u32>,
    /// 1-based line numbers that were reachable but not executed.
    pub uncovered_lines: std::collections::BTreeSet<u32>,
}

impl FileCoverage {
    /// Fraction of covered / (covered + uncovered) lines.  Returns 1.0 if
    /// there are no tracked lines.
    pub fn line_coverage_pct(&self) -> f64 {
        let total = self.covered_lines.len() + self.uncovered_lines.len();
        if total == 0 {
            return 1.0;
        }
        self.covered_lines.len() as f64 / total as f64
    }
}

/// Map a byte offset in a source file to a 1-based line number.
pub fn offset_to_line(source: &str, byte_offset: usize) -> u32 {
    let capped = byte_offset.min(source.len());
    source[..capped].chars().filter(|&c| c == '\n').count() as u32 + 1
}

// ---------------------------------------------------------------------------
// SourceCoverageReport — per-contract source-level coverage
// ---------------------------------------------------------------------------

/// Source-level coverage report for all contracts in a campaign.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct SourceCoverageReport {
    /// Contract address → per-file line coverage.
    pub contracts: HashMap<Address, ContractSourceCoverage>,
}

/// Per-contract source coverage (may span multiple source files via inheritance).
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ContractSourceCoverage {
    pub contract_name: Option<String>,
    /// Source file path → line hit counts.
    pub files: HashMap<String, FileLineCoverage>,
}

/// Per-file line coverage — maps 1-based line numbers to hit counts.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct FileLineCoverage {
    /// 1-based line → hit count.
    pub lines: HashMap<u32, u32>,
}

impl FileLineCoverage {
    pub fn record_hit(&mut self, line: u32) {
        *self.lines.entry(line).or_insert(0) += 1;
    }
}

impl SourceCoverageReport {
    /// Build a source coverage report from a coverage map + contract metadata.
    ///
    /// `contract_source_maps` maps contract address → `(bytecode, source_map_str,
    /// source_file_list, contract_name)`.  `source_file_contents` maps file
    /// path → source text (for offset-to-line conversion).
    pub fn build(
        coverage_map: &crate::types::CoverageMap,
        contract_source_maps: &HashMap<
            Address,
            (Vec<u8>, String, Vec<String>, Option<String>),
        >,
        source_file_contents: &HashMap<String, String>,
    ) -> Self {
        let mut report = Self::default();

        for (addr, edges) in &coverage_map.map {
            let Some((bytecode, src_map_str, file_list, contract_name)) =
                contract_source_maps.get(addr)
            else {
                continue;
            };

            let bsm = BytecodeSourceMap::new(bytecode, src_map_str);
            let mut contract_cov = ContractSourceCoverage {
                contract_name: contract_name.clone(),
                files: HashMap::new(),
            };

            // Collect all PCs that were hit (any edge ending at that PC).
            let mut hit_pcs: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
            for ((_, current_pc), count) in edges.iter() {
                if *count > 0 {
                    hit_pcs.insert(*current_pc);
                }
            }

            for pc in hit_pcs {
                let Some(entry) = bsm.entry_for_pc(pc) else {
                    continue;
                };
                if entry.file_index < 0 || entry.start < 0 {
                    continue; // generated code, no source
                }
                let file_idx = entry.file_index as usize;
                let Some(file_path) = file_list.get(file_idx) else {
                    continue;
                };
                let byte_offset = entry.start as usize;
                let line = if let Some(src) = source_file_contents.get(file_path) {
                    offset_to_line(src, byte_offset)
                } else {
                    // No source content — approximate line from offset
                    // (will be inaccurate, but still useful as a PC trace).
                    byte_offset as u32 + 1
                };

                contract_cov
                    .files
                    .entry(file_path.clone())
                    .or_default()
                    .record_hit(line);
            }

            if !contract_cov.files.is_empty() {
                report.contracts.insert(*addr, contract_cov);
            }
        }

        report
    }

    /// Save the report as `{dir}/source_coverage.json`.
    pub fn save_to_dir(&self, dir: &std::path::Path) -> std::io::Result<()> {
        if let Err(e) = std::fs::create_dir_all(dir) {
            tracing::warn!("[coverage] could not create dir {}: {e}", dir.display());
            return Err(e);
        }
        let path = dir.join("source_coverage.json");
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        std::fs::write(&path, json)?;
        tracing::info!("[coverage] saved source coverage to {}", path.display());
        Ok(())
    }

    /// Print a compact summary to stderr.
    pub fn print_summary(&self) {
        for (addr, cov) in &self.contracts {
            let name = cov.contract_name.as_deref().unwrap_or("(unknown)");
            for (file, fc) in &cov.files {
                let hit = fc.lines.len();
                let total_hits: u32 = fc.lines.values().sum();
                eprintln!(
                    "[coverage] {name} ({addr:#x}) | {file} | {hit} line(s) hit, {total_hits} total hits"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Artifact source map extraction
// ---------------------------------------------------------------------------

/// Extract the deployed bytecode source map from a Foundry artifact JSON value.
pub fn extract_deployed_source_map(artifact: &serde_json::Value) -> Option<String> {
    // Foundry: evm.deployedBytecode.sourceMap
    if let Some(s) = artifact
        .pointer("/evm/deployedBytecode/sourceMap")
        .and_then(|v| v.as_str())
    {
        return Some(s.to_owned());
    }
    // Solc direct output: deployedBytecode.sourceMap
    if let Some(s) = artifact
        .pointer("/deployedBytecode/sourceMap")
        .and_then(|v| v.as_str())
    {
        return Some(s.to_owned());
    }
    None
}

/// Extract the source file list from a Foundry artifact's metadata.
///
/// Returns the ordered list used to interpret `file_index` values in source
/// map entries.  Foundry stores this under
/// `metadata.settings.compilationTarget` (single file) or
/// `metadata.sources` (multi-file).
pub fn extract_source_file_list(artifact: &serde_json::Value) -> Vec<String> {
    // Try metadata.sources (full solc output)
    if let Some(sources) = artifact.pointer("/metadata/sources").and_then(|v| v.as_object()) {
        // solc orders sources by their numeric id; collect and sort.
        let mut entries: Vec<(u32, String)> = sources
            .iter()
            .filter_map(|(path, meta)| {
                let id = meta.get("id")?.as_u64()? as u32;
                Some((id, path.clone()))
            })
            .collect();
        entries.sort_by_key(|(id, _)| *id);
        return entries.into_iter().map(|(_, path)| path).collect();
    }

    // Fallback: single-file from compilationTarget
    if let Some(target) = artifact
        .pointer("/compilationTarget")
        .and_then(|v| v.as_object())
    {
        return target.keys().cloned().collect();
    }

    Vec::new()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_source_map() {
        let sm = "0:10:0:-:0;5:3:0;20:7:1";
        let entries = parse_source_map(sm);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].start, 0);
        assert_eq!(entries[0].length, 10);
        assert_eq!(entries[0].file_index, 0);
        assert_eq!(entries[1].start, 5);
        assert_eq!(entries[1].length, 3);
        assert_eq!(entries[1].file_index, 0); // inherited
        assert_eq!(entries[2].file_index, 1);
    }

    #[test]
    fn parse_inherited_fields() {
        // All fields omitted after first = inherit from previous
        let sm = "100:20:2:i:0;;;";
        let entries = parse_source_map(sm);
        assert_eq!(entries.len(), 4);
        for e in &entries {
            assert_eq!(e.start, 100);
            assert_eq!(e.file_index, 2);
        }
    }

    #[test]
    fn build_pc_table_push1() {
        // PUSH1 0x42 STOP  →  instructions: [0]=PUSH1 at pc=0, [1]=STOP at pc=2
        let bytecode = &[0x60u8, 0x42, 0x00];
        let table = build_pc_to_instruction_index(bytecode);
        assert_eq!(table[0], Some(0)); // PUSH1
        assert_eq!(table[1], None);    // data byte
        assert_eq!(table[2], Some(1)); // STOP
    }

    #[test]
    fn bytecode_source_map_lookup() {
        // PUSH1 0x42 STOP, source map: "0:10:0;5:3:0"
        let bytecode = &[0x60u8, 0x42, 0x00];
        let bsm = BytecodeSourceMap::new(bytecode, "0:10:0;5:3:0");
        // pc=0 → instr 0 → entry 0
        assert_eq!(bsm.entry_for_pc(0).unwrap().start, 0);
        // pc=1 → None (PUSH data)
        assert!(bsm.entry_for_pc(1).is_none());
        // pc=2 → instr 1 → entry 1
        assert_eq!(bsm.entry_for_pc(2).unwrap().start, 5);
    }

    #[test]
    fn offset_to_line_basic() {
        let src = "line1\nline2\nline3";
        assert_eq!(offset_to_line(src, 0), 1);
        assert_eq!(offset_to_line(src, 6), 2);  // 'l' of line2
        assert_eq!(offset_to_line(src, 12), 3); // 'l' of line3
    }
}

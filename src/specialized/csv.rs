// This file is part of the uutils file package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

use crate::specialized::elf::SpecializedResult;

pub fn test_csv(buffer: &[u8]) -> Option<SpecializedResult> {
    let s = std::str::from_utf8(buffer.get(..buffer.len().min(8192)).unwrap_or(buffer)).ok()?;
    let lines: Vec<&str> = s.lines().map(|l| l.trim()).filter(|l| !l.is_empty()).collect();

    if lines.len() < 2 {
        return None;
    }

    // Try comma first
    let comma_counts: Vec<usize> = lines.iter().map(|l| l.matches(',').count()).collect();
    if comma_counts[0] >= 1 && comma_counts.iter().all(|&c| c == comma_counts[0]) {
        return Some(SpecializedResult {
            description: "CSV text".to_string(),
            mime_type: "text/csv".to_string(),
            mime_encoding: "us-ascii".to_string(),
            extensions: "csv".to_string(),
            apple: "TEXTcsv ".to_string(),
        });
    }

    // Try tab (TSV)
    let tab_counts: Vec<usize> = lines.iter().map(|l| l.matches('\t').count()).collect();
    if tab_counts[0] >= 1 && tab_counts.iter().all(|&c| c == tab_counts[0]) {
        return Some(SpecializedResult {
            description: "TSV text".to_string(),
            mime_type: "text/tab-separated-values".to_string(),
            mime_encoding: "us-ascii".to_string(),
            extensions: "tsv".to_string(),
            apple: "TEXTtsv ".to_string(),
        });
    }

    None
}

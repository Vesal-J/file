// This file is part of the uutils file package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

use crate::specialized::elf::SpecializedResult;

pub fn test_cdf(buffer: &[u8]) -> Option<SpecializedResult> {
    // Magic: 0xD0CF11E0A1B11AE1
    if !buffer.starts_with(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1") {
        return None;
    }

    // Check directory entries / known streams within first sector or buffer
    // Scan for sub-strings indicating Word, Excel, PowerPoint, MSI
    let (desc, mime, ext) = if buffer.windows(16).any(|w| w == b"WordDocument\0\0\0\0")
        || buffer.windows(14).any(|w| w == b"W\0o\0r\0d\0D\0o\0c\0")
    {
        (
            "Composite Document File V2 Document, Little Endian, Os: Windows, Version 4.10, Microsoft Word Document",
            "application/msword",
            "doc",
        )
    } else if buffer.windows(16).any(|w| w == b"Workbook\0\0\0\0\0\0\0\0")
        || buffer.windows(16).any(|w| w == b"W\0o\0r\0k\0b\0o\0o\0k\0")
    {
        (
            "Composite Document File V2 Document, Little Endian, Os: Windows, Version 4.10, Microsoft Excel Worksheet",
            "application/vnd.ms-excel",
            "xls",
        )
    } else if buffer.windows(16).any(|w| w == b"PowerPoint Docum")
        || buffer.windows(16).any(|w| w == b"P\0o\0w\0e\0r\0P\0o\0i\0")
    {
        (
            "Composite Document File V2 Document, Little Endian, Os: Windows, Version 4.10, Microsoft PowerPoint Presentation",
            "application/vnd.ms-powerpoint",
            "ppt",
        )
    } else {
        (
            "Composite Document File V2 Document",
            "application/x-ole-storage",
            "bin",
        )
    };

    Some(SpecializedResult {
        description: desc.to_string(),
        mime_type: mime.to_string(),
        mime_encoding: "binary".to_string(),
        extensions: ext.to_string(),
        apple: "UNKNUNKN".to_string(),
    })
}

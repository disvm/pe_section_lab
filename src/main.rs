use flate2::{Compression, write::ZlibEncoder};
use std::{env, fs, io::Write, path::Path};

const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
const SECTION_HEADER_SIZE: usize = 40;

#[derive(Debug, Clone)]
struct PeInfo {
    section_count: usize,
    section_table_offset: usize,
}

#[derive(Debug, Clone)]
struct Section {
    header_offset: usize,
    name: [u8; 8],
    raw_size: u32,
    raw_ptr: u32,
    characteristics: u32,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args_os().skip(1);
    let input = args
        .next()
        .ok_or_else(|| usage("missing input .exe path"))?;
    let output = args
        .next()
        .ok_or_else(|| usage("missing output .exe path"))?;

    if args.next().is_some() {
        return Err(usage("too many arguments"));
    }

    transform_pe(Path::new(&input), Path::new(&output))
}

fn usage(reason: &str) -> String {
    format!(
        "{reason}\n\nusage:\n  pe-section-yapper <input.exe> <output.exe>\n\nexample:\n  cargo run -- target\\debug\\pe_section_lab.exe packed-demo.exe"
    )
}

fn transform_pe(input: &Path, output: &Path) -> Result<(), String> {
    let mut bytes =
        fs::read(input).map_err(|err| format!("cannot read {}: {err}", input.display()))?;
    let pe = parse_pe(&bytes)?;
    let sections = parse_sections(&bytes, &pe)?;

    let mut touched = 0usize;

    for section in sections.iter().filter(|section| section.has_raw_data()) {
        let raw_start = section.raw_ptr as usize;
        let raw_size = section.raw_size as usize;

        let raw_end = raw_start
            .checked_add(raw_size)
            .ok_or_else(|| "section raw range overflowed".to_string())?;
        if raw_end > bytes.len() {
            return Err(format!(
                "section {} points outside the file: raw offset {raw_start:#x}, size {raw_size:#x}",
                section_name(&section.name)
            ));
        }

        // Tiny PE gobble: squeeze bytes, then chill in the same old section space.
        let original = bytes[raw_start..raw_end].to_vec();
        let compressed = zlib_compress(&original)?;
        if compressed.len() > raw_size {
            eprintln!(
                "note: section {} compressed from {} to {} bytes, larger than original; storing anyway with zero padding",
                section_name(&section.name),
                raw_size,
                compressed.len()
            );
        }

        bytes[raw_start..raw_end].fill(0);
        let copy_len = compressed.len().min(raw_size);
        bytes[raw_start..raw_start + copy_len].copy_from_slice(&compressed[..copy_len]);

        // Permission glow-up for the lab: keep old flags, add RWX.
        let new_characteristics = section.characteristics
            | IMAGE_SCN_MEM_READ
            | IMAGE_SCN_MEM_WRITE
            | IMAGE_SCN_MEM_EXECUTE;

        // Name wipe, no drama. Keep SizeOfRawData unchanged to avoid layout chaos.
        write_section_name_blank(&mut bytes, section.header_offset)?;
        write_u32(&mut bytes, section.header_offset + 36, new_characteristics)?;

        touched += 1;
    }

    fs::write(output, &bytes).map_err(|err| format!("cannot write {}: {err}", output.display()))?;

    println!("wrote {}", output.display());
    println!("sections touched: {touched}");
    println!("note: this is a PE section lab file, not a self-extracting runnable packer.");
    Ok(())
}

fn parse_pe(bytes: &[u8]) -> Result<PeInfo, String> {
    if bytes.len() < 0x40 || &bytes[0..2] != b"MZ" {
        return Err("not a DOS/PE file: missing MZ header".to_string());
    }

    let pe_offset = read_u32(bytes, 0x3c)? as usize;
    if pe_offset + 24 > bytes.len() || &bytes[pe_offset..pe_offset + 4] != b"PE\0\0" {
        return Err("not a PE file: missing PE signature".to_string());
    }

    let coff = pe_offset + 4;
    let section_count = read_u16(bytes, coff + 2)? as usize;
    let optional_header_size = read_u16(bytes, coff + 16)? as usize;
    let optional_header = coff + 20;
    if optional_header + optional_header_size > bytes.len() {
        return Err("optional header points outside the file".to_string());
    }

    let magic = read_u16(bytes, optional_header)?;
    if magic != 0x10b && magic != 0x20b {
        return Err(format!("unsupported optional header magic: {magic:#x}"));
    }

    let section_table_offset = optional_header + optional_header_size;

    Ok(PeInfo {
        section_count,
        section_table_offset,
    })
}

fn parse_sections(bytes: &[u8], pe: &PeInfo) -> Result<Vec<Section>, String> {
    let table_size = pe
        .section_count
        .checked_mul(SECTION_HEADER_SIZE)
        .ok_or_else(|| "section table size overflowed".to_string())?;
    if pe.section_table_offset + table_size > bytes.len() {
        return Err("section table points outside the file".to_string());
    }

    let mut sections = Vec::with_capacity(pe.section_count);
    for index in 0..pe.section_count {
        let off = pe.section_table_offset + index * SECTION_HEADER_SIZE;
        let mut name = [0u8; 8];
        name.copy_from_slice(&bytes[off..off + 8]);
        sections.push(Section {
            header_offset: off,
            name,
            raw_size: read_u32(bytes, off + 16)?,
            raw_ptr: read_u32(bytes, off + 20)?,
            characteristics: read_u32(bytes, off + 36)?,
        });
    }

    Ok(sections)
}

impl Section {
    fn has_raw_data(&self) -> bool {
        self.raw_size != 0 && self.raw_ptr != 0
    }
}

fn zlib_compress(input: &[u8]) -> Result<Vec<u8>, String> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(input)
        .map_err(|err| format!("compression failed: {err}"))?;
    encoder
        .finish()
        .map_err(|err| format!("compression finalization failed: {err}"))
}

fn section_name(name: &[u8; 8]) -> String {
    let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
    String::from_utf8_lossy(&name[..end]).to_string()
}

fn write_section_name_blank(bytes: &mut [u8], header_offset: usize) -> Result<(), String> {
    let end = header_offset + 8;
    if end > bytes.len() {
        return Err("cannot blank section name outside file".to_string());
    }
    bytes[header_offset..end].fill(0);
    Ok(())
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, String> {
    let end = offset + 2;
    let data = bytes
        .get(offset..end)
        .ok_or_else(|| format!("cannot read u16 at {offset:#x}"))?;
    Ok(u16::from_le_bytes([data[0], data[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, String> {
    let end = offset + 4;
    let data = bytes
        .get(offset..end)
        .ok_or_else(|| format!("cannot read u32 at {offset:#x}"))?;
    Ok(u32::from_le_bytes([data[0], data[1], data[2], data[3]]))
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) -> Result<(), String> {
    let end = offset + 4;
    let target = bytes
        .get_mut(offset..end)
        .ok_or_else(|| format!("cannot write u32 at {offset:#x}"))?;
    target.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn section_name_stops_at_nul() {
        assert_eq!(section_name(b".text\0\0\0"), ".text");
    }

    #[test]
    fn section_with_raw_data_needs_size_and_pointer() {
        let mut section = Section {
            header_offset: 0,
            name: *b".text\0\0\0",
            raw_size: 1,
            raw_ptr: 1,
            characteristics: 0,
        };
        assert!(section.has_raw_data());

        section.raw_size = 0;
        assert!(!section.has_raw_data());
    }
}

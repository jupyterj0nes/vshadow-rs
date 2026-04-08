//! vshadow-info: CLI tool to inspect Volume Shadow Copies in forensic disk images.
//!
//! Supports E01, dd/raw, and partition images. Reports VSS store count,
//! creation times, and volume sizes — useful for triage before full analysis.

use clap::Parser;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use vshadow::VssVolume;

#[derive(Parser)]
#[command(
    name = "vshadow-info",
    about = "Inspect Volume Shadow Copies (VSS) in forensic disk images",
    version,
    author = "Tono Diaz (@jupyterj0nes)"
)]
struct Cli {
    /// Path to the forensic image (E01, dd/raw, or partition image)
    #[arg(short, long)]
    file: String,

    /// Byte offset of the NTFS partition within the image (auto-detected if omitted)
    #[arg(short, long)]
    offset: Option<u64>,
}

fn main() {
    let cli = Cli::parse();

    println!("vshadow-info v{}", env!("CARGO_PKG_VERSION"));
    println!("Inspecting: {}", cli.file);
    println!();

    let ext = std::path::Path::new(&cli.file)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    match ext.as_str() {
        "e01" | "ex01" => {
            match ewf::EwfReader::open(&cli.file) {
                Ok(reader) => {
                    println!("Format: E01 (Expert Witness Format)");
                    println!("Image size: {:.2} GB", reader.total_size() as f64 / 1_073_741_824.0);
                    println!();
                    let mut buf = BufReader::new(reader);
                    inspect_image(&mut buf, cli.offset);
                }
                Err(e) => eprintln!("Error opening E01: {}", e),
            }
        }
        _ => {
            match File::open(&cli.file) {
                Ok(f) => {
                    let size = f.metadata().map(|m| m.len()).unwrap_or(0);
                    println!("Format: raw/dd");
                    println!("Image size: {:.2} GB", size as f64 / 1_073_741_824.0);
                    println!();
                    let mut buf = BufReader::new(f);
                    inspect_image(&mut buf, cli.offset);
                }
                Err(e) => eprintln!("Error opening file: {}", e),
            }
        }
    }
}

fn inspect_image<R: Read + Seek>(reader: &mut R, user_offset: Option<u64>) {
    let offsets = if let Some(off) = user_offset {
        println!("Using user-specified partition offset: {:#x}", off);
        vec![off]
    } else {
        println!("Searching for NTFS partitions...");
        find_ntfs_partitions(reader)
    };

    if offsets.is_empty() {
        println!("No NTFS partitions found.");
        return;
    }

    println!("Found {} NTFS partition(s)", offsets.len());
    println!();

    for (i, offset) in offsets.iter().enumerate() {
        println!("=== Partition {} (offset {:#x}, {:.2} GB) ===", i + 1, offset, *offset as f64 / 1_073_741_824.0);

        // Create an offset reader for this partition
        let current_pos = reader.seek(SeekFrom::Start(*offset)).unwrap_or(0);
        let mut partition = OffsetReader { inner: reader, offset: *offset };

        match VssVolume::new(&mut partition) {
            Ok(vss) => {
                if vss.store_count() == 0 {
                    println!("  No Volume Shadow Copies found");
                } else {
                    println!("  {} Volume Shadow Copy snapshot(s) found!", vss.store_count());
                    println!();
                    for s in 0..vss.store_count() {
                        match vss.store_info(s) {
                            Ok(info) => {
                                let guid = uuid::Uuid::from_bytes_le(info.store_id);
                                println!("  Store {}:", s);
                                println!("    GUID:          {}", guid);
                                println!("    Volume size:   {:.2} GB", info.volume_size as f64 / 1_073_741_824.0);
                                println!("    Creation time: {}", info.creation_time_utc());
                                println!("    Sequence:      {}", info.sequence);
                                println!();
                            }
                            Err(e) => println!("  Store {}: error reading info: {}", s, e),
                        }
                    }
                }
            }
            Err(vshadow::VssError::InvalidSignature) => {
                println!("  No VSS signature found (System Protection may be disabled)");
            }
            Err(e) => {
                println!("  Error reading VSS: {}", e);
            }
        }
        println!();
    }
}

const NTFS_SIG: &[u8] = b"NTFS    ";

fn find_ntfs_partitions<R: Read + Seek>(reader: &mut R) -> Vec<u64> {
    let mut partitions = Vec::new();

    // Read MBR
    let _ = reader.seek(SeekFrom::Start(0));
    let mut mbr = [0u8; 512];
    if reader.read_exact(&mut mbr).is_err() || mbr[510] != 0x55 || mbr[511] != 0xAA {
        // Try offset 0 directly
        if verify_ntfs(reader, 0) { partitions.push(0); }
        return partitions;
    }

    let part0_type = mbr[446 + 4];

    if part0_type == 0xEE {
        // GPT
        let _ = reader.seek(SeekFrom::Start(512));
        let mut gpt = [0u8; 92];
        if reader.read_exact(&mut gpt).is_ok() && &gpt[0..8] == b"EFI PART" {
            let entry_lba = u64::from_le_bytes(gpt[72..80].try_into().unwrap());
            let count = u32::from_le_bytes(gpt[80..84].try_into().unwrap());
            let size = u32::from_le_bytes(gpt[84..88].try_into().unwrap());

            for i in 0..count.min(128) {
                let off = entry_lba * 512 + i as u64 * size as u64;
                let _ = reader.seek(SeekFrom::Start(off));
                let mut entry = vec![0u8; size as usize];
                if reader.read_exact(&mut entry).is_err() { continue; }
                if entry[0..16] == [0u8; 16] { continue; }
                let first_lba = u64::from_le_bytes(entry[32..40].try_into().unwrap());
                if verify_ntfs(reader, first_lba * 512) {
                    partitions.push(first_lba * 512);
                }
            }
        }
    } else {
        // MBR
        for i in 0..4 {
            let off = 446 + i * 16;
            let ptype = mbr[off + 4];
            let lba = u32::from_le_bytes(mbr[off+8..off+12].try_into().unwrap());
            if ptype == 0x07 && lba > 0 && verify_ntfs(reader, lba as u64 * 512) {
                partitions.push(lba as u64 * 512);
            }
        }
    }

    if partitions.is_empty() && verify_ntfs(reader, 0) {
        partitions.push(0);
    }

    partitions
}

fn verify_ntfs<R: Read + Seek>(reader: &mut R, offset: u64) -> bool {
    if reader.seek(SeekFrom::Start(offset + 3)).is_err() { return false; }
    let mut sig = [0u8; 8];
    if reader.read_exact(&mut sig).is_err() { return false; }
    &sig == NTFS_SIG
}

struct OffsetReader<'a, R: Read + Seek> {
    inner: &'a mut R,
    offset: u64,
}

impl<'a, R: Read + Seek> Read for OffsetReader<'a, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}

impl<'a, R: Read + Seek> Seek for OffsetReader<'a, R> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        match pos {
            SeekFrom::Start(p) => {
                let actual = self.inner.seek(SeekFrom::Start(self.offset + p))?;
                Ok(actual - self.offset)
            }
            SeekFrom::Current(p) => {
                let actual = self.inner.seek(SeekFrom::Current(p))?;
                Ok(actual.saturating_sub(self.offset))
            }
            SeekFrom::End(p) => {
                let actual = self.inner.seek(SeekFrom::End(p))?;
                Ok(actual.saturating_sub(self.offset))
            }
        }
    }
}

//! vshadow-info: CLI tool to inspect and extract from Volume Shadow Copies
//! in forensic disk images. Supports E01, dd/raw, and partition images.

use clap::{Parser, Subcommand};
use std::fs::{self, File};
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use vshadow::VssVolume;

#[derive(Parser)]
#[command(
    name = "vshadow-info",
    about = "Inspect and extract from Volume Shadow Copies (VSS) in forensic disk images",
    version,
    author = "Tono Diaz (@jupyterj0nes)"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// List VSS stores found in a forensic image
    Info {
        /// Path to the forensic image (E01, dd/raw, or partition image)
        #[arg(short, long)]
        file: String,

        /// Byte offset of the NTFS partition (auto-detected if omitted)
        #[arg(short, long)]
        offset: Option<u64>,
    },

    /// List files inside a VSS store's NTFS filesystem
    List {
        /// Path to the forensic image
        #[arg(short, long)]
        file: String,

        /// VSS store index (0-based). Required unless --live is used.
        #[arg(short, long, default_value_t = 0)]
        store: usize,

        /// Directory path to list (default: root)
        #[arg(short, long, default_value = "")]
        path: String,

        /// Byte offset of the NTFS partition (auto-detected if omitted)
        #[arg(long)]
        offset: Option<u64>,

        /// Use live volume instead of VSS store (for comparison)
        #[arg(long)]
        live: bool,
    },

    /// Extract files from a VSS store to disk
    Extract {
        /// Path to the forensic image
        #[arg(short, long)]
        file: String,

        /// VSS store index (0-based). Ignored if --live is used.
        #[arg(short, long, default_value_t = 0)]
        store: usize,

        /// Extract from live volume instead of VSS store
        #[arg(long)]
        live: bool,

        /// Directory path to extract (e.g., "Windows/System32/winevt/Logs")
        #[arg(short, long)]
        path: String,

        /// Output directory
        #[arg(short, long)]
        output: String,

        /// Byte offset of the NTFS partition (auto-detected if omitted)
        #[arg(long)]
        offset: Option<u64>,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Info { file, offset } => cmd_info(&file, offset),
        Commands::List { file, store, path, offset, live } => cmd_list(&file, store, &path, offset, live),
        Commands::Extract { file, store, path, output, offset, live } => cmd_extract(&file, store, &path, &output, offset, live),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  INFO command
// ─────────────────────────────────────────────────────────────────────────────

fn cmd_info(file: &str, user_offset: Option<u64>) {
    println!("vshadow-info v{}", env!("CARGO_PKG_VERSION"));
    println!("Inspecting: {}", file);
    println!();

    with_reader(file, |reader, size| {
        println!("Image size: {:.2} GB", size as f64 / 1_073_741_824.0);
        println!();

        let offsets = resolve_partitions(reader, user_offset);
        if offsets.is_empty() {
            println!("No NTFS partitions found.");
            return;
        }
        println!("Found {} NTFS partition(s)", offsets.len());
        println!();

        for (i, offset) in offsets.iter().enumerate() {
            println!("=== Partition {} (offset {:#x}, {:.2} GB) ===",
                i + 1, offset, *offset as f64 / 1_073_741_824.0);

            let mut pr = OffsetReader::new(reader, *offset);
            match VssVolume::new(&mut pr) {
                Ok(vss) if vss.store_count() > 0 => {
                    println!("  {} Volume Shadow Copy snapshot(s) found!", vss.store_count());
                    println!();
                    for s in 0..vss.store_count() {
                        if let Ok(info) = vss.store_info(s) {
                            let guid = uuid::Uuid::from_bytes_le(info.store_id);
                            println!("  Store {}:", s);
                            println!("    GUID:          {}", guid);
                            println!("    Volume size:   {:.2} GB", info.volume_size as f64 / 1_073_741_824.0);
                            println!("    Creation time: {}", info.creation_time_utc());
                            println!("    Sequence:      {}", info.sequence);
                            println!();
                        }
                    }
                }
                Ok(_) => println!("  No Volume Shadow Copies found"),
                Err(vshadow::VssError::InvalidSignature) => {
                    println!("  No VSS signature (System Protection may be disabled)");
                }
                Err(e) => println!("  Error: {}", e),
            }
            println!();
        }
    });
}

// ─────────────────────────────────────────────────────────────────────────────
//  LIST command
// ─────────────────────────────────────────────────────────────────────────────

fn cmd_list(file: &str, store: usize, path: &str, user_offset: Option<u64>, live: bool) {
    with_reader(file, |reader, _| {
        let offsets = resolve_partitions(reader, user_offset);
        // Use the last NTFS partition (typically the system volume)
        let partition_offset = offsets.last().copied().unwrap_or(0);

        if live {
            println!("Listing live volume at offset {:#x}, path: /{}", partition_offset, path);
            println!();
            let mut pr = OffsetReader::new(reader, partition_offset);
            list_ntfs_dir(&mut pr, path);
        } else {
            let mut pr = OffsetReader::new(reader, partition_offset);
            match VssVolume::new(&mut pr) {
                Ok(vss) if store < vss.store_count() => {
                    println!("Listing VSS store {} at offset {:#x}, path: /{}", store, partition_offset, path);
                    println!();
                    match vss.store_reader(&mut pr, store) {
                        Ok(mut sr) => list_ntfs_dir(&mut sr, path),
                        Err(e) => eprintln!("Error opening store: {}", e),
                    }
                }
                Ok(vss) => eprintln!("Store index {} out of range (found {})", store, vss.store_count()),
                Err(e) => eprintln!("No VSS found: {}", e),
            }
        }
    });
}

fn list_ntfs_dir<R: Read + Seek>(reader: &mut R, path: &str) {
    let mut ntfs = match ntfs::Ntfs::new(reader) {
        Ok(n) => n,
        Err(e) => { eprintln!("Cannot parse NTFS: {}", e); return; }
    };
    let _ = ntfs.read_upcase_table(reader);

    let root = match ntfs.root_directory(reader) {
        Ok(r) => r,
        Err(e) => { eprintln!("Cannot read root: {}", e); return; }
    };

    // Navigate to target path
    let mut current = root;
    if !path.is_empty() {
        for component in path.split(&['/', '\\'][..]).filter(|c| !c.is_empty()) {
            let idx = match current.directory_index(reader) {
                Ok(i) => i,
                Err(e) => { eprintln!("Cannot read dir: {}", e); return; }
            };
            let mut found = false;
            let mut entries = idx.entries();
            while let Some(entry) = entries.next(reader) {
                if let Ok(entry) = entry {
                    if let Some(Ok(fname)) = entry.key() {
                        if fname.name().to_string_lossy().eq_ignore_ascii_case(component) {
                            if let Ok(f) = entry.file_reference().to_file(&ntfs, reader) {
                                current = f;
                                found = true;
                                break;
                            }
                        }
                    }
                }
            }
            if !found {
                eprintln!("Path not found: {}", component);
                return;
            }
        }
    }

    // List entries
    let idx = match current.directory_index(reader) {
        Ok(i) => i,
        Err(e) => { eprintln!("Not a directory or cannot read: {}", e); return; }
    };

    let mut entries = idx.entries();
    let mut count = 0;
    while let Some(entry) = entries.next(reader) {
        if let Ok(entry) = entry {
            if let Some(Ok(fname)) = entry.key() {
                let name = fname.name().to_string_lossy();
                let is_dir = fname.is_directory();
                let size = if !is_dir {
                    if let Ok(f) = entry.file_reference().to_file(&ntfs, reader) {
                        match f.data(reader, "") {
                            Some(Ok(d)) => d.to_attribute().map(|a| a.value_length()).unwrap_or(0),
                            _ => 0,
                        }
                    } else { 0 }
                } else { 0 };

                if is_dir {
                    println!("  [DIR]  {}", name);
                } else {
                    println!("  {:>10}  {}", format_size(size), name);
                }
                count += 1;
            }
        }
    }
    println!("\n{} entries", count);
}

// ─────────────────────────────────────────────────────────────────────────────
//  EXTRACT command
// ─────────────────────────────────────────────────────────────────────────────

fn cmd_extract(file: &str, store: usize, path: &str, output: &str, user_offset: Option<u64>, live: bool) {
    let _ = fs::create_dir_all(output);

    with_reader(file, |reader, _| {
        let offsets = resolve_partitions(reader, user_offset);
        let partition_offset = offsets.last().copied().unwrap_or(0);

        if live {
            println!("Extracting from live volume, path: /{}", path);
            let mut pr = OffsetReader::new(reader, partition_offset);
            let count = extract_from_ntfs(&mut pr, path, output);
            println!("Extracted {} files to {}", count, output);
        } else {
            let mut pr = OffsetReader::new(reader, partition_offset);
            match VssVolume::new(&mut pr) {
                Ok(vss) if store < vss.store_count() => {
                    println!("Extracting from VSS store {}, path: /{}", store, path);
                    match vss.store_reader(&mut pr, store) {
                        Ok(mut sr) => {
                            let count = extract_from_ntfs(&mut sr, path, output);
                            println!("Extracted {} files to {}", count, output);
                        }
                        Err(e) => eprintln!("Error opening store: {}", e),
                    }
                }
                Ok(vss) => eprintln!("Store {} out of range (found {})", store, vss.store_count()),
                Err(e) => eprintln!("No VSS found: {}", e),
            }
        }
    });
}

fn extract_from_ntfs<R: Read + Seek>(reader: &mut R, path: &str, output_dir: &str) -> usize {
    let mut ntfs = match ntfs::Ntfs::new(reader) {
        Ok(n) => n,
        Err(e) => { eprintln!("Cannot parse NTFS: {}", e); return 0; }
    };
    let _ = ntfs.read_upcase_table(reader);

    let root = match ntfs.root_directory(reader) {
        Ok(r) => r,
        Err(e) => { eprintln!("Cannot read root: {}", e); return 0; }
    };

    // Navigate to target path
    let mut current = root;
    for component in path.split(&['/', '\\'][..]).filter(|c| !c.is_empty()) {
        let idx = match current.directory_index(reader) {
            Ok(i) => i,
            Err(_) => return 0,
        };
        let mut found = false;
        let mut entries = idx.entries();
        while let Some(entry) = entries.next(reader) {
            if let Ok(entry) = entry {
                if let Some(Ok(fname)) = entry.key() {
                    if fname.name().to_string_lossy().eq_ignore_ascii_case(component) {
                        if let Ok(f) = entry.file_reference().to_file(&ntfs, reader) {
                            current = f;
                            found = true;
                            break;
                        }
                    }
                }
            }
        }
        if !found {
            eprintln!("Path not found: {}", component);
            return 0;
        }
    }

    // Extract all files in this directory
    let idx = match current.directory_index(reader) {
        Ok(i) => i,
        Err(_) => return 0,
    };

    let mut count = 0;
    let mut entries = idx.entries();
    while let Some(entry) = entries.next(reader) {
        let entry = match entry { Ok(e) => e, Err(_) => continue };
        if let Some(Ok(fname)) = entry.key() {
            if fname.is_directory() { continue; }
            let name = fname.name().to_string_lossy().to_string();

            let ntfs_file = match entry.file_reference().to_file(&ntfs, reader) {
                Ok(f) => f,
                Err(_) => continue,
            };
            let data_item = match ntfs_file.data(reader, "") {
                Some(Ok(d)) => d,
                _ => continue,
            };
            let data_attr = match data_item.to_attribute() {
                Ok(a) => a,
                Err(_) => continue,
            };
            let data_value = match data_attr.value(reader) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let mut attached = data_value.attach(reader);

            let out_path = std::path::Path::new(output_dir).join(&name);
            let mut out_file = match File::create(&out_path) {
                Ok(f) => f,
                Err(_) => continue,
            };

            let mut buf = [0u8; 65536];
            loop {
                match attached.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => { let _ = out_file.write_all(&buf[..n]); }
                    Err(_) => break,
                }
            }

            let size = out_path.metadata().map(|m| m.len()).unwrap_or(0);
            println!("  {} ({})", name, format_size(size));
            count += 1;
        }
    }

    count
}

// ─────────────────────────────────────────────────────────────────────────────
//  Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn with_reader(file: &str, f: impl FnOnce(&mut BufReader<Box<dyn ReadSeekImpl>>, u64)) {
    let ext = std::path::Path::new(file)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    match ext.as_str() {
        "e01" | "ex01" => {
            match ewf::EwfReader::open(file) {
                Ok(reader) => {
                    let size = reader.total_size();
                    println!("Format: E01 (Expert Witness Format)");
                    let boxed: Box<dyn ReadSeekImpl> = Box::new(reader);
                    let mut buf = BufReader::new(boxed);
                    f(&mut buf, size);
                }
                Err(e) => eprintln!("Error opening E01: {}", e),
            }
        }
        _ => {
            match File::open(file) {
                Ok(fh) => {
                    let size = fh.metadata().map(|m| m.len()).unwrap_or(0);
                    println!("Format: raw/dd");
                    let boxed: Box<dyn ReadSeekImpl> = Box::new(fh);
                    let mut buf = BufReader::new(boxed);
                    f(&mut buf, size);
                }
                Err(e) => eprintln!("Error opening file: {}", e),
            }
        }
    }
}

trait ReadSeekImpl: Read + Seek {}
impl<T: Read + Seek> ReadSeekImpl for T {}

fn resolve_partitions<R: Read + Seek>(reader: &mut R, user_offset: Option<u64>) -> Vec<u64> {
    if let Some(off) = user_offset {
        if verify_ntfs(reader, off) { vec![off] } else { vec![] }
    } else {
        find_ntfs_partitions(reader)
    }
}

fn format_size(bytes: u64) -> String {
    if bytes >= 1_073_741_824 { format!("{:.1} GB", bytes as f64 / 1_073_741_824.0) }
    else if bytes >= 1_048_576 { format!("{:.1} MB", bytes as f64 / 1_048_576.0) }
    else if bytes >= 1024 { format!("{:.1} KB", bytes as f64 / 1024.0) }
    else { format!("{} B", bytes) }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Partition detection (GPT + MBR)
// ─────────────────────────────────────────────────────────────────────────────

const NTFS_SIG: &[u8] = b"NTFS    ";

fn find_ntfs_partitions<R: Read + Seek>(reader: &mut R) -> Vec<u64> {
    let mut partitions = Vec::new();
    let _ = reader.seek(SeekFrom::Start(0));
    let mut mbr = [0u8; 512];
    if reader.read_exact(&mut mbr).is_err() || mbr[510] != 0x55 || mbr[511] != 0xAA {
        if verify_ntfs(reader, 0) { partitions.push(0); }
        return partitions;
    }

    if mbr[446 + 4] == 0xEE {
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
        for i in 0..4 {
            let off = 446 + i * 16;
            let ptype = mbr[off + 4];
            let lba = u32::from_le_bytes(mbr[off+8..off+12].try_into().unwrap());
            if ptype == 0x07 && lba > 0 && verify_ntfs(reader, lba as u64 * 512) {
                partitions.push(lba as u64 * 512);
            }
        }
    }
    if partitions.is_empty() && verify_ntfs(reader, 0) { partitions.push(0); }
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

impl<'a, R: Read + Seek> OffsetReader<'a, R> {
    fn new(inner: &'a mut R, offset: u64) -> Self { Self { inner, offset } }
}

impl<'a, R: Read + Seek> Read for OffsetReader<'a, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> { self.inner.read(buf) }
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

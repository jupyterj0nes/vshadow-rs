//! vshadow-rs: CLI tool to inspect, list, extract, and timeline from Volume Shadow Copies
//! in forensic disk images. Supports E01, dd/raw, and partition images.

use clap::{Parser, Subcommand};
use std::fs::{self, File};
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::time::Instant;
use vshadow::VssVolume;

#[derive(Parser)]
#[command(
    name = "vshadow-rs",
    about = "Inspect, extract, and timeline from Volume Shadow Copies (VSS) in forensic disk images",
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

    /// List files inside a VSS store's NTFS filesystem (recursive by default)
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

        /// Do not recurse into subdirectories (list one level only)
        #[arg(long)]
        no_recursive: bool,
    },

    /// Show only files that exist in VSS but were deleted or changed on the live volume
    ListDelta {
        /// Path to the forensic image
        #[arg(short, long)]
        file: String,

        /// VSS store index (0-based, default: all stores)
        #[arg(short, long)]
        store: Option<usize>,

        /// Directory path to focus the delta on (default: whole filesystem)
        #[arg(short, long, default_value = "")]
        path: String,

        /// Byte offset of the NTFS partition (auto-detected if omitted)
        #[arg(long)]
        offset: Option<u64>,

        /// Output CSV file (instead of console display)
        #[arg(short, long)]
        output: Option<String>,
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

    /// Generate a MACB timeline CSV from all VSS stores in a forensic image
    Timeline {
        /// Path to the forensic image
        #[arg(short, long)]
        file: String,

        /// Output CSV file (default: stdout)
        #[arg(short, long)]
        output: Option<String>,

        /// Byte offset of the NTFS partition (auto-detected if omitted)
        #[arg(long)]
        offset: Option<u64>,

        /// Also include the live volume (not just VSS stores)
        #[arg(long)]
        include_live: bool,

        /// Output format: "expanded" (8 rows per file with SI+FN) or "macb" (1 row per file)
        #[arg(long, default_value = "expanded")]
        format: String,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Info { file, offset } => cmd_info(&file, offset),
        Commands::List { file, store, path, offset, live, no_recursive } => {
            cmd_list(&file, store, &path, offset, live, no_recursive)
        }
        Commands::ListDelta { file, store, path, offset, output } => {
            cmd_list_delta(&file, store, &path, offset, output.as_deref())
        }
        Commands::Extract { file, store, path, output, offset, live } => {
            cmd_extract(&file, store, &path, &output, offset, live)
        }
        Commands::Timeline { file, output, offset, include_live, format } => {
            cmd_timeline(&file, output.as_deref(), offset, include_live, &format)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  INFO command
// ─────────────────────────────────────────────────────────────────────────────

const BANNER: &[&str] = &[
    // Lines 0-13: helmet — G=green(34), else=white(255)
    r"                                         GGGGGGG",
    r"                                   GGG  GGGGGGG  GGG",
    r"                               GGGGGGG  GGGGGGG  GGGGGGG",
    r"                             GGGGGGGGG           GGGGGGGGG",
    r"                           GGGGGGGGGG  ADBhhhBAB  GGGGGGGGGG",
    r"                         GGGGGGGGGGh  AhhBBBBOhhA  GGGGGGGGGG",
    r"                        GGGGGGGGGGG  ChhBHVRTHBhhA  GGGGGGGGGG",
    r"                       GGGGGGGGGGG   AhEBUVUUUBBhA   GGGGGGGGGG",
    r"                       GGGGGGGGGGG   AhhBBIRJBEhhA  GGGGGGGGGGGG",
    r"                      GGGGGGGGGGGG    AUhhJPBhhBA    GGGGGGGGGGGG",
    r"                     GGGGGGGGGGGGGG     AABBBAA   GGGGGGGGGGGGGGGG",
    r"                    GGGGGGGGGGGGGGGGGG           GGGGGGGGGGGGGGGGGG",
    r"                   GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG",
    r"                 GGGGG                                           GGGGG",
    // Lines 14-15: eyes — A=white(255), h=orange(208), else=yellow(220)
    r"                         hhh   AAA                  AAAA   hhh       ",
    r"                      hhhhh    AAA   hhhhhhhhhhhhh   AA    hhhhhh",
    // Lines 16-21: body — entire line orange(208)
    r"                   hhhhhhhh          hhhhhhhhhhhhh          hhhhhhh",
    r"         hhhhhhh    hhhhhhhh        hhhhhhhhhhhhhh         hhhhhhhh    hhhhhhh",
    r"      hhhhhhhhhhhh   hhhhhhhh      hhhhhhhhhhhhhhhhh     hhhhhhhhh   hhhhhhhhhhhh",
    r"    hhhhhhhhhhhhhhhh   hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh   hhhhhhhhhhhhhhhh",
    r"   hhhhhhhhhhhhhhhhhh        hhhhhhhhhhhhhhhhhhhhhhhhhhhhhh       hhhhhhhhhhhhhhhhhh",
    r"  hhhhhhhh        hhhh                 hhhhh                     hhhh        hhhhhhhh",
    // Lines 22-34: mixed — h=orange(208), else=yellow(220)
    r" hhhhh      hhhh            GGGGGGGGz                                  hhhh      hhhhh",
    r" hhh    hhhhhhhhhhh        GGYZVYYYGG                               hhhhhhhhhhh    hhh",
    r" hh   hhhhhhhhhh        GGGGZZZZWWYZGGGGGGGGGGGGGGGGGGGGGGGGGGG        hhhhhhhhhh   hh",
    r" h   hhhhhhhhhh   hhhhh    GGGXYYYYXXX1111111ZZZZY11ZZXXYGGG    hhhhh   hhhhhhhhhh   h",
    r"     hhhhhhhhhh  hhhhhhhhh   GGYYYYYYXXXXWYYXZZ1111XXXXWGG   hhhhhhhhh  hhhhhhhhhh",
    r"    hhhhhhhhhhh  hhhhhhhhhhh  GGYYYYYYYXXW1ZY1XXXXXXYYXGG  hhhhhhhhhhh  hhhhhhhhhhh",
    r"     hhhhhhhhhh   hhhhhhhhhhh  GGXYYYYYX21111XXYYYYYYYGG  hhhhhhhhhhh   hhhhhhhhhh",
    r"     hhhhhhhhhhhh    hhhhhhhhh  GWYYYXXXXXXXXXYYYYYXXXG  hhhhhhhhh    hhhhhhhhhhhh",
    r"      hhhhhhhhhhhh           h  GTXYVMMPZYYYYXXYYQQP2NG  h           hhhhhhhhhhhh",
    r"       hhhhhhhhhhhhh      GG    USXWXkkPWMGGGGMVTLkRWO    iGG      hhhhhhhhhhhhh",
    r"        hhhhhhhhhhhhh     GGGGGGGGGGLMLMOGkkkkN66XPKOMGGGGGGG     hhhhhhhhhhhhh",
    r"          hhhhhhhhhhhhh    GGGOZPkkkLZWXQkkkkkK331UkQ6UUJGGG    hhhhhhhhhhhh",
    r"              hhhhhhhhhhhh   nOXLGGGIUZWOGGGGGGQWJGGGKX9N    hhhhhhhhhhhh",
    // Lines 35-37: bottom file — entire line yellow(220)
    r"                             GS22YRGkGGGOZW4SkkQQkkkkkHkGG",
    r"                          GGGGGGGGGGGGIGGGGGGGGGGGGGGGGGGGGGG",
    r"                          GGGGGGGGGGGGIGGGGGGGGGGGGGGGGGGGGGG",
    // Line 38: empty
    r"",
    // Lines 39-46: text "vshadow-rs" — entire line white(255)
    r"                    A                         A",
    r"                  AAA                       AAA",
    r"                  AHA                       AJA",
    r"AA    AA  AAAAAA  AQAAAAAA   AAAAAAA  eAAAAAAMA  AAAAAAA AAA  AA   AA      AAAAA pAAAAAA",
    r"AAA  AAA  AAD     AQA   AAA       BA  AAA   AJA AAA   AA  AA  AAA AAA      ANA   AAA",
    r" AAJ AA    AAAAA  AAA   AAA AAAAAAtA  At    AAA AAA   AWA AAA AMA AA  AAAA AAA     AAAAA",
    r"  MMyWA        3A AAA   AAA Aat   BB  AVA  S8AA A4A   AA   AffA AA0A       AAA        fAx",
    r"  AAAA   AAAAAAA  AAA   AAA  AAAAAAA   AAAAAAAA   AAAAA    AAA  AAA        AAA   AAAAAAA",
];

fn print_banner() {
    eprintln!();
    for (idx, line) in BANNER.iter().enumerate() {
        if line.is_empty() {
            eprintln!();
        } else if idx <= 13 {
            // Helmet: G=yellow, everything else=white
            for ch in line.chars() {
                if ch == ' ' { eprint!(" "); }
                else if ch == 'G' { eprint!("\x1b[38;5;220m{}\x1b[0m", ch); }
                else { eprint!("\x1b[38;5;255m{}\x1b[0m", ch); }
            }
            eprintln!();
        } else if idx <= 15 {
            // Eyes: A=white, h=orange, else=yellow
            for ch in line.chars() {
                if ch == ' ' { eprint!(" "); }
                else if ch == 'A' { eprint!("\x1b[38;5;255m{}\x1b[0m", ch); }
                else if ch == 'h' { eprint!("\x1b[38;5;208m{}\x1b[0m", ch); }
                else { eprint!("\x1b[38;5;220m{}\x1b[0m", ch); }
            }
            eprintln!();
        } else if idx <= 21 {
            // Body: entire line orange
            eprintln!("\x1b[38;5;208m{}\x1b[0m", line);
        } else if idx <= 34 {
            // Mixed: h=orange, else=folder blue
            for ch in line.chars() {
                if ch == ' ' { eprint!(" "); }
                else if ch == 'h' { eprint!("\x1b[38;5;208m{}\x1b[0m", ch); }
                else { eprint!("\x1b[38;5;33m{}\x1b[0m", ch); }
            }
            eprintln!();
        } else if idx <= 37 {
            // Bottom file: entire line folder blue
            eprintln!("\x1b[38;5;33m{}\x1b[0m", line);
        } else {
            // Text: entire line white
            eprintln!("\x1b[38;5;255m{}\x1b[0m", line);
        }
    }
    eprintln!();
    eprintln!("        \x1b[1;38;5;208mv\x1b[38;5;172ms\x1b[38;5;172mh\x1b[38;5;166ma\x1b[38;5;166md\x1b[38;5;130mo\x1b[38;5;130mw\x1b[38;5;130m-\x1b[38;5;130mr\x1b[38;5;130ms\x1b[0m v{}", env!("CARGO_PKG_VERSION"));
    eprintln!("        \x1b[2midentify, timeline and recover files from the shadows\x1b[0m");
    eprintln!("        \x1b[2mby Tono Diaz (@jupyterj0nes) | weinvestigateanything.com\x1b[0m");
    eprintln!();
}

fn cmd_info(file: &str, user_offset: Option<u64>) {
    print_banner();
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
            println!("=== Partition {} ===", i + 1);
            println!("  Offset:          {:#x} ({:.2} GB into disk)", offset, *offset as f64 / 1_073_741_824.0);

            let mut pr = OffsetReader::new(reader, *offset);
            match VssVolume::new(&mut pr) {
                Ok(vss) if vss.store_count() > 0 => {
                    println!("  VSS detected:    YES (signature found at partition offset 0x1E00)");
                    println!("  Snapshots:       {}", vss.store_count());
                    println!();
                    for s in 0..vss.store_count() {
                        if let Ok(info) = vss.store_info(s) {
                            let guid = uuid::Uuid::from_bytes_le(info.store_id);
                            println!("  Store {}:", s);
                            println!("    GUID:            {}", guid);
                            println!("    Created:         {}", info.creation_time_utc());
                            println!("    Sequence:        {}", info.sequence);

                            // Show delta size (changed blocks)
                            match vss.store_delta_size(&mut pr, s) {
                                Ok((blocks, bytes)) => {
                                    println!("    Changed blocks:  {} ({} modified since snapshot)",
                                        blocks, format_size(bytes));
                                }
                                Err(_) => {}
                            }
                            println!();
                        }
                    }
                }
                Ok(_) => {
                    println!("  VSS detected:    NO (signature present but no stores found)");
                }
                Err(vshadow::VssError::InvalidSignature) => {
                    println!("  VSS detected:    NO (no VSS signature at partition offset 0x1E00)");
                    println!("                   System Protection was likely disabled on this volume");
                }
                Err(e) => println!("  VSS detected:    ERROR ({})", e),
            }
            println!();
        }
    });
}

// ─────────────────────────────────────────────────────────────────────────────
//  LIST command
// ─────────────────────────────────────────────────────────────────────────────

fn cmd_list(file: &str, store: usize, path: &str, user_offset: Option<u64>, live: bool, no_recursive: bool) {
    print_banner();
    with_reader(file, |reader, _| {
        let offsets = resolve_partitions(reader, user_offset);
        // Use the last NTFS partition (typically the system volume)
        let partition_offset = offsets.last().copied().unwrap_or(0);

        if live {
            println!("Listing live volume at offset {:#x}, path: /{}", partition_offset, path);
            println!();
            let mut pr = OffsetReader::new(reader, partition_offset);
            if no_recursive {
                list_ntfs_dir_flat(&mut pr, path);
            } else {
                list_ntfs_dir_recursive(&mut pr, path);
            }
        } else {
            let mut pr = OffsetReader::new(reader, partition_offset);
            match VssVolume::new(&mut pr) {
                Ok(vss) if store < vss.store_count() => {
                    println!("Listing VSS store {} at offset {:#x}, path: /{}", store, partition_offset, path);
                    println!();
                    match vss.store_reader(&mut pr, store) {
                        Ok(mut sr) => {
                            if no_recursive {
                                list_ntfs_dir_flat(&mut sr, path);
                            } else {
                                list_ntfs_dir_recursive(&mut sr, path);
                            }
                        }
                        Err(e) => eprintln!("Error opening store: {}", e),
                    }
                }
                Ok(vss) => eprintln!("Store index {} out of range (found {})", store, vss.store_count()),
                Err(e) => eprintln!("No VSS found: {}", e),
            }
        }
    });
}

/// Navigate to a given path within NTFS, returning the NtfsFile at that path.
/// Returns None if the path cannot be found.
fn navigate_to_path<'n, R: Read + Seek>(
    ntfs: &'n ntfs::Ntfs,
    reader: &mut R,
    path: &str,
) -> Option<ntfs::NtfsFile<'n>> {
    let root = match ntfs.root_directory(reader) {
        Ok(r) => r,
        Err(e) => { eprintln!("Cannot read root: {}", e); return None; }
    };

    let mut current = root;
    if !path.is_empty() {
        for component in path.split(&['/', '\\'][..]).filter(|c| !c.is_empty()) {
            let idx = match current.directory_index(reader) {
                Ok(i) => i,
                Err(e) => { eprintln!("Cannot read dir: {}", e); return None; }
            };
            let mut found = false;
            let mut entries = idx.entries();
            while let Some(entry) = entries.next(reader) {
                if let Ok(entry) = entry {
                    if let Some(Ok(fname)) = entry.key() {
                        if fname.name().to_string_lossy().eq_ignore_ascii_case(component) {
                            if let Ok(f) = entry.file_reference().to_file(ntfs, reader) {
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
                return None;
            }
        }
    }
    Some(current)
}

/// List entries in a single directory (non-recursive, original behavior).
fn list_ntfs_dir_flat<R: Read + Seek>(reader: &mut R, path: &str) {
    let mut ntfs = match ntfs::Ntfs::new(reader) {
        Ok(n) => n,
        Err(e) => { eprintln!("Cannot parse NTFS: {}", e); return; }
    };
    let _ = ntfs.read_upcase_table(reader);

    let current = match navigate_to_path(&ntfs, reader, path) {
        Some(f) => f,
        None => return,
    };

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

/// Recursively list all entries starting from the given path.
fn list_ntfs_dir_recursive<R: Read + Seek>(reader: &mut R, path: &str) {
    let mut ntfs = match ntfs::Ntfs::new(reader) {
        Ok(n) => n,
        Err(e) => { eprintln!("Cannot parse NTFS: {}", e); return; }
    };
    let _ = ntfs.read_upcase_table(reader);

    let current = match navigate_to_path(&ntfs, reader, path) {
        Some(f) => f,
        None => return,
    };

    let prefix = if path.is_empty() { String::new() } else { format!("{}/", path.trim_end_matches('/')) };
    let mut count = 0;
    list_recursive_walk(&ntfs, reader, &current, &prefix, &mut count);
    println!("\n{} entries (recursive)", count);
}

fn list_recursive_walk<R: Read + Seek>(
    ntfs: &ntfs::Ntfs,
    reader: &mut R,
    dir: &ntfs::NtfsFile<'_>,
    prefix: &str,
    count: &mut usize,
) {
    let idx = match dir.directory_index(reader) {
        Ok(i) => i,
        Err(_) => return,
    };

    // Collect entries first to avoid borrow conflicts
    let mut children: Vec<(String, bool, u64, u64)> = Vec::new(); // (name, is_dir, size, file_record_number)
    let mut entries = idx.entries();
    while let Some(entry) = entries.next(reader) {
        if let Ok(entry) = entry {
            if let Some(Ok(fname)) = entry.key() {
                let name = fname.name().to_string_lossy().to_string();
                // Skip NTFS internal entries
                if name == "." || name == ".." {
                    continue;
                }
                let is_dir = fname.is_directory();
                let frn = entry.file_reference().file_record_number();
                let size = if !is_dir {
                    if let Ok(f) = entry.file_reference().to_file(ntfs, reader) {
                        match f.data(reader, "") {
                            Some(Ok(d)) => d.to_attribute().map(|a| a.value_length()).unwrap_or(0),
                            _ => 0,
                        }
                    } else { 0 }
                } else { 0 };
                children.push((name, is_dir, size, frn));
            }
        }
    }

    for (name, is_dir, size, frn) in &children {
        let full_path = format!("{}{}", prefix, name);
        if *is_dir {
            println!("  [DIR]  {}", full_path);
        } else {
            println!("  {:>10}  {}", format_size(*size), full_path);
        }
        *count += 1;

        // Recurse into subdirectories (skip MFT metadata file record numbers < 24)
        if *is_dir && *frn >= 24 {
            if let Ok(sub) = ntfs.file(reader, *frn) {
                let sub_prefix = format!("{}/", full_path);
                list_recursive_walk(ntfs, reader, &sub, &sub_prefix, count);
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  EXTRACT command
// ─────────────────────────────────────────────────────────────────────────────

fn cmd_list_delta(file: &str, store_filter: Option<usize>, path: &str, user_offset: Option<u64>, csv_output: Option<&str>) {
    print_banner();
    let start = Instant::now();

    with_reader(file, |reader, _| {
        let offsets = resolve_partitions(reader, user_offset);
        let partition_offset = offsets.last().copied().unwrap_or(0);

        eprintln!("  Inspecting: {}", file);
        eprintln!("  NTFS partition at offset {:#x} ({:.2} GB into disk)", partition_offset, partition_offset as f64 / 1_073_741_824.0);
        eprintln!();

        // Step 1: Index live volume
        if path.is_empty() {
            eprintln!("[1/3] Indexing live volume...");
        } else {
            eprintln!("[1/3] Indexing live volume (path: /{})...", path);
        }
        let mut pr = OffsetReader::new(reader, partition_offset);
        let mut live_index: std::collections::HashMap<String, (u64, String)> = std::collections::HashMap::new();
        index_ntfs_files(&mut pr, path, &mut live_index);
        eprintln!("        {} files indexed on live volume", live_index.len());

        // Step 2: Detect VSS stores
        eprintln!();
        eprintln!("[2/3] Detecting VSS stores...");
        match VssVolume::new(&mut pr) {
            Ok(vss) if vss.store_count() > 0 => {
                eprintln!("        {} VSS store(s) found", vss.store_count());
                for s in 0..vss.store_count() {
                    if let Ok(info) = vss.store_info(s) {
                        let guid = uuid::Uuid::from_bytes_le(info.store_id);
                        eprintln!("        Store {}: created {} | GUID: {}", s, info.creation_time_utc(), guid);
                        if let Ok((blocks, bytes)) = vss.store_delta_size(&mut pr, s) {
                            eprintln!("                 {} changed blocks ({} delta)", blocks, format_size(bytes));
                        }
                    }
                }

                let stores_to_process: Vec<usize> = match store_filter {
                    Some(s) => vec![s],
                    None => (0..vss.store_count()).collect(),
                };

                // Open CSV writer if --output specified
                let mut csv_writer: Option<Box<dyn Write>> = if let Some(out_path) = csv_output {
                    match File::create(out_path) {
                        Ok(f) => {
                            let mut w: Box<dyn Write> = Box::new(std::io::BufWriter::new(f));
                            let _ = writeln!(w, "status,si_modified,size_vss,size_live,path,source,vss_created");
                            eprintln!("  CSV output: {}", out_path);
                            Some(w)
                        }
                        Err(e) => {
                            eprintln!("Cannot create output file: {}", e);
                            return;
                        }
                    }
                } else {
                    None
                };

                let mut total_deleted: usize = 0;
                let mut total_changed: usize = 0;

                for s in stores_to_process {
                    if s >= vss.store_count() {
                        eprintln!("Store {} out of range (found {})", s, vss.store_count());
                        continue;
                    }

                    let vss_created = vss.store_info(s)
                        .map(|info| info.creation_time_utc())
                        .unwrap_or_default();

                    eprintln!();
                    eprintln!("[3/3] Comparing VSS store {} against live volume...", s);
                    eprintln!("        Indexing VSS store filesystem...");

                    match vss.store_reader(&mut pr, s) {
                        Ok(mut sr) => {
                            // Build VSS index
                            let mut vss_index: std::collections::HashMap<String, (u64, String)> = std::collections::HashMap::new();
                            index_ntfs_files(&mut sr, path, &mut vss_index);
                            eprintln!("        {} files indexed on VSS store", vss_index.len());
                            eprintln!("        Computing delta...");

                            let mut deleted = Vec::new();
                            let mut changed = Vec::new();

                            for (fpath, (vss_size, vss_mod)) in &vss_index {
                                match live_index.get(fpath) {
                                    None => deleted.push((fpath.clone(), *vss_size, vss_mod.clone())),
                                    Some((live_size, live_mod)) => {
                                        if vss_size != live_size || vss_mod != live_mod {
                                            changed.push((fpath.clone(), *vss_size, *live_size, vss_mod.clone()));
                                        }
                                    }
                                }
                            }

                            deleted.sort();
                            changed.sort();

                            total_deleted += deleted.len();
                            total_changed += changed.len();

                            let source = format!("vss_{}", s);

                            if let Some(ref mut w) = csv_writer {
                                // CSV output mode
                                for (fpath, size, ts) in &deleted {
                                    let _ = writeln!(w, "deleted,{},{},,{},{},{}", ts, size, csv_escape(fpath), &source, vss_created);
                                }
                                for (fpath, vss_size, live_size, ts) in &changed {
                                    let _ = writeln!(w, "changed,{},{},{},{},{},{}", ts, vss_size, live_size, csv_escape(fpath), &source, vss_created);
                                }
                            } else {
                                // Console output mode
                                eprintln!("\n=== VSS Store {} (created {}) ===", s, vss_created);

                                if !deleted.is_empty() {
                                    eprintln!("\n  DELETED ({} files — exist in VSS but not on live):", deleted.len());
                                    for (fpath, size, ts) in &deleted {
                                        println!("  [DELETED]  {}  {:>10}  {}", ts, format_size(*size), fpath);
                                    }
                                }

                                if !changed.is_empty() {
                                    eprintln!("\n  CHANGED ({} files — different size or timestamp):", changed.len());
                                    for (fpath, vss_size, live_size, ts) in &changed {
                                        println!("  [CHANGED]  {}  {:>10} -> {:>10}  {}", ts, format_size(*vss_size), format_size(*live_size), fpath);
                                    }
                                }

                                if deleted.is_empty() && changed.is_empty() {
                                    eprintln!("  No differences found");
                                } else {
                                    eprintln!("\n  Total: {} deleted, {} changed", deleted.len(), changed.len());
                                }
                            }
                        }
                        Err(e) => eprintln!("  Error opening store: {}", e),
                    }
                }

                let elapsed = start.elapsed().as_secs_f64();
                eprintln!();
                eprintln!("  ──────────────────────────────────────────────────");
                eprintln!("  Deleted files:   {}", total_deleted);
                eprintln!("  Changed files:   {}", total_changed);
                eprintln!("  Completed in:    {:.1}s", elapsed);
            }
            Ok(_) => eprintln!("No VSS stores found"),
            Err(e) => eprintln!("No VSS: {}", e),
        }
    });
}

fn cmd_extract(file: &str, store: usize, path: &str, output: &str, user_offset: Option<u64>, live: bool) {
    print_banner();
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
//  TIMELINE command
// ─────────────────────────────────────────────────────────────────────────────

/// Convert an NtfsTime (100-nanosecond intervals since 1601-01-01) to "YYYY-MM-DD HH:MM:SS" UTC.
fn ntfs_time_to_string(t: ntfs::NtfsTime) -> String {
    let nt = t.nt_timestamp();
    if nt == 0 {
        return "0000-00-00 00:00:00".to_string();
    }
    let secs_since_1601 = nt / 10_000_000;
    // Seconds between 1601-01-01 and 1970-01-01
    let epoch_diff: u64 = 11_644_473_600;
    if secs_since_1601 < epoch_diff {
        return "0000-00-00 00:00:00".to_string();
    }
    let unix_secs = secs_since_1601 - epoch_diff;

    // Convert unix timestamp to date/time components
    // Using a simple algorithm for UTC date conversion
    let secs_in_day: u64 = 86400;
    let mut days = unix_secs / secs_in_day;
    let day_secs = unix_secs % secs_in_day;
    let hours = day_secs / 3600;
    let minutes = (day_secs % 3600) / 60;
    let seconds = day_secs % 60;

    // Days since 1970-01-01 to y/m/d (civil_from_days algorithm)
    // Shift epoch from 1970-01-01 to 0000-03-01
    days += 719468;
    let era = days / 146097;
    let doe = days - era * 146097; // day of era [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // year of era [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // day of year [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // day [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // month [1, 12]
    let y = if m <= 2 { y + 1 } else { y };

    format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", y, m, d, hours, minutes, seconds)
}

/// Escape a CSV field: if it contains comma, quote, or newline, wrap in double quotes.
fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn cmd_timeline(file: &str, output: Option<&str>, user_offset: Option<u64>, include_live: bool, format: &str) {
    print_banner();
    let use_macb = format == "macb";

    with_reader(file, |reader, _| {
        let offsets = resolve_partitions(reader, user_offset);
        let partition_offset = offsets.last().copied().unwrap_or(0);

        // Open CSV writer
        let mut csv_out: Box<dyn Write> = if let Some(out_path) = output {
            match File::create(out_path) {
                Ok(f) => {
                    eprintln!("Writing timeline to: {}", out_path);
                    Box::new(std::io::BufWriter::new(f))
                }
                Err(e) => {
                    eprintln!("Cannot create output file: {}", e);
                    return;
                }
            }
        } else {
            Box::new(std::io::BufWriter::new(std::io::stdout()))
        };

        // Write CSV header
        if use_macb {
            let _ = writeln!(csv_out, "size,macb,path,is_dir,source,status,si_created,si_modified,si_accessed,si_mft_modified,fn_created,fn_modified,fn_accessed,fn_mft_modified");
        } else {
            let _ = writeln!(csv_out, "timestamp,timestamp_type,macb,size,path,is_dir,source,vss_created");
        }

        let mut pr = OffsetReader::new(reader, partition_offset);

        // Step 1: Build index of live volume files (path -> size + timestamps)
        eprintln!("  Indexing live volume...");
        let mut live_index: std::collections::HashMap<String, (u64, String)> = std::collections::HashMap::new();
        index_ntfs_files(&mut pr, "", &mut live_index);
        eprintln!("    {} files indexed on live volume", live_index.len());

        // Step 2: Detect VSS stores
        let vss_result = VssVolume::new(&mut pr);
        let vss_stores = match &vss_result {
            Ok(vss) if vss.store_count() > 0 => {
                eprintln!("  Found {} VSS store(s)", vss.store_count());
                vss.store_count()
            }
            _ => {
                eprintln!("  No VSS stores found");
                0
            }
        };

        if vss_stores == 0 {
            eprintln!("Nothing to do — no VSS stores found.");
            return;
        }

        // Step 3: For each VSS store, only output files that differ from live
        if let Ok(ref vss) = vss_result {
            for s in 0..vss_stores {
                let source = format!("vss_{}", s);
                let vss_created = vss.store_info(s)
                    .map(|info| info.creation_time_utc())
                    .unwrap_or_default();

                eprintln!("  Processing VSS store {} (created {})...", s, vss_created);
                eprintln!("    Comparing against live volume to find deleted/changed files...");

                match vss.store_reader(&mut pr, s) {
                    Ok(mut sr) => {
                        diff_timeline_from_ntfs(&mut sr, "", &source, &vss_created, use_macb, &live_index, &mut csv_out);
                    }
                    Err(e) => eprintln!("    Error: {}", e),
                }
            }
        }

        // Optionally include live volume too
        if include_live {
            eprintln!("  Including live volume...");
            timeline_from_ntfs(&mut pr, "", "live", "", use_macb, &mut csv_out);
        }
    });
}

/// Build an index of all files on a volume: path -> (size, si_modified timestamp)
fn index_ntfs_files<R: Read + Seek>(reader: &mut R, path: &str, index: &mut std::collections::HashMap<String, (u64, String)>) {
    let mut ntfs = match ntfs::Ntfs::new(reader) {
        Ok(n) => n,
        Err(_) => return,
    };
    let _ = ntfs.read_upcase_table(reader);

    let root = match navigate_to_path(&ntfs, reader, path) {
        Some(f) => f,
        None => return,
    };

    let prefix = if path.is_empty() { String::new() } else { format!("{}/", path.trim_end_matches('/')) };
    index_walk(&ntfs, reader, &root, &prefix, index);
}

fn index_walk<R: Read + Seek>(
    ntfs: &ntfs::Ntfs,
    reader: &mut R,
    dir: &ntfs::NtfsFile<'_>,
    prefix: &str,
    index: &mut std::collections::HashMap<String, (u64, String)>,
) {
    let idx = match dir.directory_index(reader) {
        Ok(i) => i,
        Err(_) => return,
    };

    let mut children: Vec<(String, bool, u64, u64)> = Vec::new();
    let mut entries = idx.entries();
    while let Some(entry) = entries.next(reader) {
        if let Ok(entry) = entry {
            if let Some(Ok(fname)) = entry.key() {
                let name = fname.name().to_string_lossy().to_string();
                if name == "." || name == ".." { continue; }
                let is_dir = fname.is_directory();
                let frn = entry.file_reference().file_record_number();
                let size = if !is_dir {
                    if let Ok(f) = entry.file_reference().to_file(ntfs, reader) {
                        match f.data(reader, "") {
                            Some(Ok(d)) => d.to_attribute().map(|a| a.value_length()).unwrap_or(0),
                            _ => 0,
                        }
                    } else { 0 }
                } else { 0 };
                children.push((name, is_dir, size, frn));
            }
        }
    }

    for (name, is_dir, size, frn) in &children {
        let full_path = format!("{}{}", prefix, name);

        let si_mod = if let Ok(f) = ntfs.file(reader, *frn) {
            if let Ok(si) = f.info() {
                ntfs_time_to_string(si.modification_time())
            } else { String::new() }
        } else { String::new() };

        index.insert(full_path.clone(), (*size, si_mod));

        if *is_dir && *frn >= 24 {
            if let Ok(sub) = ntfs.file(reader, *frn) {
                let sub_prefix = format!("{}/", full_path);
                index_walk(ntfs, reader, &sub, &sub_prefix, index);
            }
        }
    }
}

/// Generate timeline only for files that differ between VSS and live (deleted or changed)
fn diff_timeline_from_ntfs<R: Read + Seek>(
    reader: &mut R,
    path: &str,
    source: &str,
    vss_created: &str,
    use_macb: bool,
    live_index: &std::collections::HashMap<String, (u64, String)>,
    csv_out: &mut dyn Write,
) {
    let mut ntfs = match ntfs::Ntfs::new(reader) {
        Ok(n) => n,
        Err(e) => { eprintln!("    Cannot parse NTFS: {}", e); return; }
    };
    let _ = ntfs.read_upcase_table(reader);

    let current = match navigate_to_path(&ntfs, reader, path) {
        Some(f) => f,
        None => return,
    };

    let prefix = if path.is_empty() { String::new() } else { format!("{}/", path.trim_end_matches('/')) };
    let mut total: u64 = 0;
    let mut diff_count: u64 = 0;
    let mut deleted_count: u64 = 0;
    let mut changed_count: u64 = 0;
    diff_timeline_walk(&ntfs, reader, &current, &prefix, source, vss_created, use_macb, live_index, csv_out, &mut total, &mut diff_count, &mut deleted_count, &mut changed_count);
    eprintln!("    {} total files scanned, {} differences found ({} deleted, {} changed)",
        total, diff_count, deleted_count, changed_count);
}

fn diff_timeline_walk<R: Read + Seek>(
    ntfs: &ntfs::Ntfs,
    reader: &mut R,
    dir: &ntfs::NtfsFile<'_>,
    prefix: &str,
    source: &str,
    vss_created: &str,
    use_macb: bool,
    live_index: &std::collections::HashMap<String, (u64, String)>,
    csv_out: &mut dyn Write,
    total: &mut u64,
    diff_count: &mut u64,
    deleted_count: &mut u64,
    changed_count: &mut u64,
) {
    let idx = match dir.directory_index(reader) {
        Ok(i) => i,
        Err(_) => return,
    };

    let mut children: Vec<(String, bool, u64, u64)> = Vec::new();
    let mut entries = idx.entries();
    while let Some(entry) = entries.next(reader) {
        if let Ok(entry) = entry {
            if let Some(Ok(fname)) = entry.key() {
                let name = fname.name().to_string_lossy().to_string();
                if name == "." || name == ".." { continue; }
                let is_dir = fname.is_directory();
                let frn = entry.file_reference().file_record_number();
                let size = if !is_dir {
                    if let Ok(f) = entry.file_reference().to_file(ntfs, reader) {
                        match f.data(reader, "") {
                            Some(Ok(d)) => d.to_attribute().map(|a| a.value_length()).unwrap_or(0),
                            _ => 0,
                        }
                    } else { 0 }
                } else { 0 };
                children.push((name, is_dir, size, frn));
            }
        }
    }

    for (name, is_dir, size, frn) in &children {
        let full_path = format!("{}{}", prefix, name);
        *total += 1;

        // Check if this file differs from live
        let is_different = if *is_dir {
            // Only include dirs that don't exist on live
            !live_index.contains_key(&full_path)
        } else {
            match live_index.get(&full_path) {
                None => true, // deleted from live
                Some((live_size, live_si_mod)) => {
                    // Check if size or modification time differs
                    let vss_si_mod = if let Ok(f) = ntfs.file(reader, *frn) {
                        if let Ok(si) = f.info() {
                            ntfs_time_to_string(si.modification_time())
                        } else { String::new() }
                    } else { String::new() };
                    *size != *live_size || vss_si_mod != *live_si_mod
                }
            }
        };

        if is_different && !is_dir {
            *diff_count += 1;
            if !live_index.contains_key(&full_path) {
                *deleted_count += 1;
            } else {
                *changed_count += 1;
            }

            let is_dir_str = "false";
            let escaped_path = csv_escape(&full_path);

            let ntfs_file = match ntfs.file(reader, *frn) {
                Ok(f) => f,
                Err(_) => continue,
            };

            let (si_c, si_m, si_a, si_mft) = if let Ok(si) = ntfs_file.info() {
                (
                    ntfs_time_to_string(si.creation_time()),
                    ntfs_time_to_string(si.modification_time()),
                    ntfs_time_to_string(si.access_time()),
                    ntfs_time_to_string(si.mft_record_modification_time()),
                )
            } else {
                (String::new(), String::new(), String::new(), String::new())
            };

            let (fn_c, fn_m, fn_a, fn_mft) = if let Some(Ok(fn_attr)) = ntfs_file.name(reader, None, None) {
                (
                    ntfs_time_to_string(fn_attr.creation_time()),
                    ntfs_time_to_string(fn_attr.modification_time()),
                    ntfs_time_to_string(fn_attr.access_time()),
                    ntfs_time_to_string(fn_attr.mft_record_modification_time()),
                )
            } else {
                (String::new(), String::new(), String::new(), String::new())
            };

            let status = if live_index.contains_key(&full_path) { "changed" } else { "deleted" };

            if use_macb {
                let _ = writeln!(csv_out, "{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
                    size, "MACB", escaped_path, is_dir_str, source, status,
                    si_c, si_m, si_a, si_mft, fn_c, fn_m, fn_a, fn_mft);
            } else {
                let rows = [
                    (&si_m, "SI_Modified", "M..."),
                    (&si_a, "SI_Accessed", ".A.."),
                    (&si_mft, "SI_MFTModified", "..C."),
                    (&si_c, "SI_Created", "...B"),
                    (&fn_m, "FN_Modified", "M..."),
                    (&fn_a, "FN_Accessed", ".A.."),
                    (&fn_mft, "FN_MFTModified", "..C."),
                    (&fn_c, "FN_Created", "...B"),
                ];
                for (ts, ts_type, macb) in &rows {
                    if !ts.is_empty() {
                        let _ = writeln!(csv_out, "{},{},{},{},{},{},{},{}",
                            ts, ts_type, macb, size, escaped_path, is_dir_str, source, vss_created);
                    }
                }
            }
        }

        // Always recurse into directories
        if *is_dir && *frn >= 24 {
            if let Ok(sub) = ntfs.file(reader, *frn) {
                let sub_prefix = format!("{}/", full_path);
                diff_timeline_walk(ntfs, reader, &sub, &sub_prefix, source, vss_created, use_macb, live_index, csv_out, total, diff_count, deleted_count, changed_count);
            }
        }
    }
}

fn timeline_from_ntfs<R: Read + Seek>(reader: &mut R, path: &str, source: &str, vss_created: &str, use_macb: bool, csv_out: &mut dyn Write) {
    let mut ntfs = match ntfs::Ntfs::new(reader) {
        Ok(n) => n,
        Err(e) => { eprintln!("    Cannot parse NTFS: {}", e); return; }
    };
    let _ = ntfs.read_upcase_table(reader);

    let current = match navigate_to_path(&ntfs, reader, path) {
        Some(f) => f,
        None => return,
    };

    let prefix = if path.is_empty() { String::new() } else { format!("{}/", path.trim_end_matches('/')) };
    let mut count: u64 = 0;
    timeline_walk(&ntfs, reader, &current, &prefix, source, vss_created, use_macb, csv_out, &mut count);
    eprintln!("    {} entries processed", count);
}

fn timeline_walk<R: Read + Seek>(
    ntfs: &ntfs::Ntfs,
    reader: &mut R,
    dir: &ntfs::NtfsFile<'_>,
    prefix: &str,
    source: &str,
    vss_created: &str,
    use_macb: bool,
    csv_out: &mut dyn Write,
    count: &mut u64,
) {
    let idx = match dir.directory_index(reader) {
        Ok(i) => i,
        Err(_) => return,
    };

    let mut children: Vec<(String, bool, u64, u64)> = Vec::new();
    let mut entries = idx.entries();
    while let Some(entry) = entries.next(reader) {
        if let Ok(entry) = entry {
            if let Some(Ok(fname)) = entry.key() {
                let name = fname.name().to_string_lossy().to_string();
                if name == "." || name == ".." { continue; }
                let is_dir = fname.is_directory();
                let frn = entry.file_reference().file_record_number();
                let size = if !is_dir {
                    if let Ok(f) = entry.file_reference().to_file(ntfs, reader) {
                        match f.data(reader, "") {
                            Some(Ok(d)) => d.to_attribute().map(|a| a.value_length()).unwrap_or(0),
                            _ => 0,
                        }
                    } else { 0 }
                } else { 0 };
                children.push((name, is_dir, size, frn));
            }
        }
    }

    for (name, is_dir, size, frn) in &children {
        let full_path = format!("{}{}", prefix, name);
        let is_dir_str = if *is_dir { "true" } else { "false" };
        let escaped_path = csv_escape(&full_path);

        let ntfs_file = match ntfs.file(reader, *frn) {
            Ok(f) => f,
            Err(_) => continue,
        };

        // Get all 8 timestamps
        let (si_c, si_m, si_a, si_mft) = if let Ok(si) = ntfs_file.info() {
            (
                ntfs_time_to_string(si.creation_time()),
                ntfs_time_to_string(si.modification_time()),
                ntfs_time_to_string(si.access_time()),
                ntfs_time_to_string(si.mft_record_modification_time()),
            )
        } else {
            (String::new(), String::new(), String::new(), String::new())
        };

        let (fn_c, fn_m, fn_a, fn_mft) = if let Some(Ok(fn_attr)) = ntfs_file.name(reader, None, None) {
            (
                ntfs_time_to_string(fn_attr.creation_time()),
                ntfs_time_to_string(fn_attr.modification_time()),
                ntfs_time_to_string(fn_attr.access_time()),
                ntfs_time_to_string(fn_attr.mft_record_modification_time()),
            )
        } else {
            (String::new(), String::new(), String::new(), String::new())
        };

        if use_macb {
            // macb format: one row per file with all timestamps as columns
            // size,macb,path,is_dir,source,si_created,si_modified,si_accessed,si_mft_modified,fn_created,fn_modified,fn_accessed,fn_mft_modified
            let macb = "MACB"; // all timestamps present
            let _ = writeln!(csv_out, "{},{},{},{},{},{},{},{},{},{},{},{},{}",
                size, macb, escaped_path, is_dir_str, source,
                si_c, si_m, si_a, si_mft, fn_c, fn_m, fn_a, fn_mft);
        } else {
            // expanded format: 8 rows per file
            // timestamp,timestamp_type,macb,size,path,is_dir,source,vss_created
            let rows = [
                (&si_m, "SI_Modified", "M..."),
                (&si_a, "SI_Accessed", ".A.."),
                (&si_mft, "SI_MFTModified", "..C."),
                (&si_c, "SI_Created", "...B"),
                (&fn_m, "FN_Modified", "M..."),
                (&fn_a, "FN_Accessed", ".A.."),
                (&fn_mft, "FN_MFTModified", "..C."),
                (&fn_c, "FN_Created", "...B"),
            ];
            for (ts, ts_type, macb) in &rows {
                if !ts.is_empty() {
                    let _ = writeln!(csv_out, "{},{},{},{},{},{},{},{}",
                        ts, ts_type, macb, size, escaped_path, is_dir_str, source, vss_created);
                }
            }
        }

        *count += 1;

        if *is_dir && *frn >= 24 {
            if let Ok(sub) = ntfs.file(reader, *frn) {
                let sub_prefix = format!("{}/", full_path);
                timeline_walk(ntfs, reader, &sub, &sub_prefix, source, vss_created, use_macb, csv_out, count);
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Resolve an input path that might be a device, volume, or mount point.
/// Returns (resolved_path, is_device).
fn resolve_device_path(input: &str) -> (String, bool) {
    // Windows: \\.\PhysicalDriveN or \\.\X: → already a device path
    if input.starts_with("\\\\.\\") {
        return (input.to_string(), true);
    }

    // Windows: bare drive letter (D: or D:\) → convert to \\.\D:
    #[cfg(windows)]
    {
        let trimmed = input.trim_end_matches(&['\\', '/'][..]);
        if trimmed.len() == 2
            && trimmed.as_bytes()[0].is_ascii_alphabetic()
            && trimmed.as_bytes()[1] == b':'
        {
            let device = format!("\\\\.\\{}", trimmed);
            println!("Resolved {} \u{2192} {}", input, device);
            return (device, true);
        }
    }

    // Linux/macOS: /dev/xxx → device path
    #[cfg(unix)]
    {
        if input.starts_with("/dev/") {
            return (input.to_string(), true);
        }

        // Try to resolve mount point via /proc/mounts (Linux)
        if let Ok(content) = std::fs::read_to_string("/proc/mounts") {
            let input_clean = input.trim_end_matches('/');
            for line in content.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let mount_point = parts[1].trim_end_matches('/');
                    if mount_point == input_clean && parts[0].starts_with("/dev/") {
                        println!("Resolved mount point {} \u{2192} {}", input, parts[0]);
                        return (parts[0].to_string(), true);
                    }
                }
            }
        }

        // macOS: use diskutil or stat to resolve mount points
        #[cfg(target_os = "macos")]
        {
            if std::path::Path::new(input).is_dir() {
                if let Ok(output) = std::process::Command::new("df").arg(input).output() {
                    if let Ok(stdout) = String::from_utf8(output.stdout) {
                        if let Some(last_line) = stdout.lines().last() {
                            let dev = last_line.split_whitespace().next().unwrap_or("");
                            if dev.starts_with("/dev/") {
                                println!("Resolved mount point {} \u{2192} {}", input, dev);
                                return (dev.to_string(), true);
                            }
                        }
                    }
                }
            }
        }
    }

    (input.to_string(), false)
}

// ─────────────────────────────────────────────────────────────────────────────
//  Sector-aligned reader for raw device I/O
// ─────────────────────────────────────────────────────────────────────────────

/// Windows volume/disk handles require sector-aligned reads.
/// This wrapper handles alignment transparently.
struct SectorReader {
    inner: File,
    sector_size: usize,
    cache: Vec<u8>,
    cache_start: u64,
    cache_len: usize,
    pos: u64,
    size: u64,
}

impl SectorReader {
    fn new(inner: File, sector_size: usize, size: u64) -> Self {
        Self {
            inner,
            sector_size,
            cache: vec![0u8; sector_size * 128], // 64 KB cache
            cache_start: u64::MAX,
            cache_len: 0,
            pos: 0,
            size,
        }
    }

    fn fill_cache(&mut self, offset: u64) -> std::io::Result<()> {
        let aligned = (offset / self.sector_size as u64) * self.sector_size as u64;
        // Check if already cached
        if self.cache_start != u64::MAX
            && aligned >= self.cache_start
            && aligned < self.cache_start + self.cache_len as u64
        {
            return Ok(());
        }
        self.inner.seek(SeekFrom::Start(aligned))?;
        self.cache_len = self.inner.read(&mut self.cache)?;
        self.cache_start = aligned;
        Ok(())
    }
}

impl Read for SectorReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.size > 0 && self.pos >= self.size {
            return Ok(0);
        }
        let mut total = 0;
        while total < buf.len() {
            self.fill_cache(self.pos)?;
            if self.cache_start == u64::MAX || self.cache_len == 0 {
                break;
            }
            let offset_in_cache = (self.pos - self.cache_start) as usize;
            if offset_in_cache >= self.cache_len {
                break;
            }
            let available = self.cache_len - offset_in_cache;
            let to_copy = (buf.len() - total).min(available);
            buf[total..total + to_copy]
                .copy_from_slice(&self.cache[offset_in_cache..offset_in_cache + to_copy]);
            self.pos += to_copy as u64;
            total += to_copy;
        }
        Ok(total)
    }
}

impl Seek for SectorReader {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.pos = match pos {
            SeekFrom::Start(n) => n,
            SeekFrom::End(n) => {
                if self.size > 0 {
                    (self.size as i64 + n) as u64
                } else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Unsupported,
                        "cannot seek from end: device size unknown",
                    ));
                }
            }
            SeekFrom::Current(n) => (self.pos as i64 + n) as u64,
        };
        Ok(self.pos)
    }
}

/// Get device/volume size using platform-specific methods.
fn get_device_size(file: &File) -> u64 {
    #[cfg(windows)]
    {
        get_device_size_ioctl(file)
    }
    #[cfg(not(windows))]
    {
        // On Unix, clone the fd and seek to end
        if let Ok(mut dup) = file.try_clone() {
            let size = dup.seek(SeekFrom::End(0)).unwrap_or(0);
            let _ = dup.seek(SeekFrom::Start(0));
            size
        } else {
            0
        }
    }
}

#[cfg(windows)]
fn get_device_size_ioctl(file: &File) -> u64 {
    use std::os::windows::io::AsRawHandle;

    const IOCTL_DISK_GET_LENGTH_INFO: u32 = 0x0007405C;

    extern "system" {
        fn DeviceIoControl(
            hDevice: isize,
            dwIoControlCode: u32,
            lpInBuffer: *const u8,
            nInBufferSize: u32,
            lpOutBuffer: *mut u8,
            nOutBufferSize: u32,
            lpBytesReturned: *mut u32,
            lpOverlapped: *const u8,
        ) -> i32;
    }

    let mut length: i64 = 0;
    let mut returned: u32 = 0;

    let result = unsafe {
        DeviceIoControl(
            file.as_raw_handle() as isize,
            IOCTL_DISK_GET_LENGTH_INFO,
            std::ptr::null(),
            0,
            &mut length as *mut i64 as *mut u8,
            std::mem::size_of::<i64>() as u32,
            &mut returned,
            std::ptr::null(),
        )
    };

    if result != 0 && length > 0 {
        length as u64
    } else {
        0
    }
}

fn with_reader(file: &str, f: impl FnOnce(&mut BufReader<Box<dyn ReadSeekImpl>>, u64)) {
    // First check if this is a device path, volume, or mount point
    let (resolved, is_device) = resolve_device_path(file);

    if is_device {
        match File::open(&resolved) {
            Ok(fh) => {
                let size = get_device_size(&fh);

                if resolved.contains("PhysicalDrive") || resolved.contains("physicaldrive") {
                    println!("Format: physical disk ({})", resolved);
                } else if resolved.starts_with("/dev/") {
                    println!("Format: block device ({})", resolved);
                } else {
                    println!("Format: volume ({})", resolved);
                }

                if size == 0 {
                    eprintln!();
                    eprintln!("Error: could not determine device size.");
                    #[cfg(windows)]
                    eprintln!("Make sure you are running as Administrator.");
                    #[cfg(unix)]
                    eprintln!("Make sure you are running with sudo.");
                    return;
                }

                println!("Volume size: {:.2} GB", size as f64 / 1_073_741_824.0);

                // Wrap in sector-aligned reader (required for Windows raw device I/O)
                let sector = SectorReader::new(fh, 512, size);
                let boxed: Box<dyn ReadSeekImpl> = Box::new(sector);
                let mut buf = BufReader::new(boxed);
                f(&mut buf, size);
            }
            Err(e) => {
                eprintln!("Error opening device {}: {}", resolved, e);
                #[cfg(windows)]
                eprintln!("Hint: opening disk devices requires running as Administrator");
                #[cfg(unix)]
                eprintln!("Hint: opening block devices requires root privileges (try sudo)");
            }
        }
        return;
    }

    // Regular file handling
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

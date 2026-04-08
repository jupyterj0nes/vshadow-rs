# vshadow-rs

<div align="center">
  <strong>Pure Rust parser for Windows Volume Shadow Copy (VSS) snapshots</strong>
  <br><br>

  [![Crates.io](https://img.shields.io/crates/v/vshadow.svg)](https://crates.io/crates/vshadow)
  [![License](https://img.shields.io/badge/License-MIT%2FApache--2.0-blue.svg)]()
  [![Rust](https://img.shields.io/badge/Rust-000000?logo=rust&logoColor=white)](https://www.rust-lang.org/)
  [![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)]()

</div>

---

Read-only access to Windows Volume Shadow Copy (VSS) snapshots from any `Read + Seek` source — forensic disk images (E01, dd), raw partitions, or mounted volumes. **No Windows APIs required.** Works on Linux, macOS, and Windows.

> Part of the [We Investigate Anything](https://weinvestigateanything.com) project. Used by [masstin](https://github.com/jupyterj0nes/masstin) for forensic image analysis.

## Why?

During incident response, attackers frequently clear Windows event logs. But if Volume Shadow Copies exist on the disk, the old logs are still there — frozen in time inside the shadow copy snapshots. Existing tools have limitations:

| Tool | Limitation |
|------|-----------|
| **vshadowmount** | Requires FUSE, Linux only |
| **EVTXECmd --vss** | Requires Windows VSS COM API, live systems only |
| **Both** | Cannot read from E01 forensic images directly |

**vshadow-rs** reads the VSS on-disk format directly, giving you cross-platform access to shadow copy data from any forensic image format.

## Install

### As a CLI tool

```bash
cargo install vshadow
```

Or download prebuilt binaries from the [Releases page](https://github.com/jupyterj0nes/vshadow-rs/releases).

### As a library

```toml
[dependencies]
vshadow = "0.1"
```

## CLI Usage

vshadow-info has three subcommands:

### Inspect VSS stores

```bash
# Auto-detects NTFS partitions (GPT and MBR)
vshadow-info info -f evidence.E01

# Specify partition offset manually
vshadow-info info -f disk.dd --offset 0x26700000
```

Example output:

```
vshadow-info v0.1.0
Inspecting: evidence.E01

Format: E01 (Expert Witness Format)
Image size: 476.94 GB

Found 2 NTFS partition(s)

=== Partition 1 (offset 0x100000, 0.00 GB) ===
  No VSS signature (System Protection may be disabled)

=== Partition 2 (offset 0x26700000, 0.60 GB) ===
  3 Volume Shadow Copy snapshot(s) found!

  Store 0:
    GUID:          a1b2c3d4-e5f6-7890-abcd-ef1234567890
    Volume size:   475.00 GB
    Creation time: ~19150 days since epoch, 14:23:01 UTC
    Sequence:      1
```

### List files

Browse directories inside the live volume or any VSS store:

```bash
# List EVTX files in the live volume
vshadow-info list -f evidence.E01 --live -p "Windows/System32/winevt/Logs"

# List EVTX files in VSS store 0 (snapshot)
vshadow-info list -f evidence.E01 -s 0 -p "Windows/System32/winevt/Logs"

# List root directory
vshadow-info list -f evidence.E01 --live
```

Example output:

```
Listing live volume at offset 0x0, path: /Windows/System32/winevt/Logs

      1.1 MB  Application.evtx
     68.0 KB  HardwareEvents.evtx
      1.1 MB  Security.evtx
      1.1 MB  System.evtx
     68.0 KB  Windows PowerShell.evtx

196 entries
```

### Extract files

Extract files from the live volume or any VSS store to a local directory:

```bash
# Extract EVTX from the live volume
vshadow-info extract -f evidence.E01 --live -p "Windows/System32/winevt/Logs" -o ./evtx_live/

# Extract EVTX from VSS store 0 (recover deleted logs!)
vshadow-info extract -f evidence.E01 -s 0 -p "Windows/System32/winevt/Logs" -o ./evtx_vss0/

# Extract from a raw/dd image
vshadow-info extract -f disk.dd --live -p "Windows/System32/winevt/Logs" -o ./output/
```

### Typical forensic workflow

```bash
# 1. Check what VSS stores exist
vshadow-info info -f suspect.E01

# 2. Compare Security.evtx size between live and VSS (cleared logs = smaller file)
vshadow-info list -f suspect.E01 --live -p "Windows/System32/winevt/Logs"
vshadow-info list -f suspect.E01 -s 0 -p "Windows/System32/winevt/Logs"

# 3. Extract EVTX from the VSS snapshot (before the attacker cleared them)
vshadow-info extract -f suspect.E01 -s 0 -p "Windows/System32/winevt/Logs" -o ./recovered/

# 4. Parse with masstin for lateral movement timeline
masstin -a parse-windows -d ./recovered/ -o timeline.csv
```

## Library Usage

```rust
use std::fs::File;
use std::io::BufReader;
use vshadow::VssVolume;

let f = File::open("partition.raw")?;
let mut reader = BufReader::new(f);

let volume = VssVolume::new(&mut reader)?;
println!("Found {} VSS snapshots", volume.store_count());

for i in 0..volume.store_count() {
    let info = volume.store_info(i)?;
    println!("Store {}: sequence {}", i, info.sequence);

    // Get a reader that presents the volume as it was at snapshot time
    let mut store_reader = volume.store_reader(&mut reader, i)?;
    // store_reader implements Read + Seek — pass to ntfs crate, etc.
}
```

### Integration with forensic crates

```rust
// E01 -> partition -> VSS store -> NTFS -> files
let ewf = ewf::EwfReader::open("evidence.E01")?;
let mut partition = OffsetReader::new(ewf, partition_offset);

let vss = VssVolume::new(&mut partition)?;
for i in 0..vss.store_count() {
    let mut store = vss.store_reader(&mut partition, i)?;
    let ntfs = ntfs::Ntfs::new(&mut store)?;
    // Navigate directories, extract files from the snapshot...
}
```

## Supported formats

| Image format | How |
|-------------|-----|
| E01 (Expert Witness Format) | Via `ewf` crate (included in CLI) |
| Raw / dd | Native `std::fs::File` |
| VMDK, VHD, QCOW2 | Any crate that provides `Read + Seek` |
| Partition images | Direct (no partition table parsing needed) |

## Supported Windows versions

- Windows Vista / Server 2008 (VSS v1)
- Windows 7 / Server 2008 R2 (VSS v1)
- Windows 8 / Server 2012 (VSS v2)
- Windows 10 / 11 / Server 2016-2022 (VSS v2)

## Comparison with existing tools

| Feature | vshadowmount | vshadowinfo | **vshadow-info** |
|---------|-------------|-------------|-----------------|
| List VSS stores | No | Yes | **Yes** |
| Show GUIDs, dates | No | Yes | **Yes** |
| Mount as filesystem (FUSE) | Yes | No | No |
| **List files in VSS store** | Via mount | No | **Yes** |
| **Extract files from VSS** | Via mount | No | **Yes** |
| **List files in live volume** | No | No | **Yes** |
| **Read E01 directly** | No | No | **Yes** |
| **Auto-detect GPT/MBR partitions** | No | No | **Yes** |
| Cross-platform | Linux only | Linux/Mac/Win | **Win/Linux/Mac** |

## How VSS works

Volume Shadow Copy uses a copy-on-write mechanism at the block level (16 KiB blocks):

1. **Snapshot creation**: the catalog records metadata for the snapshot (GUID, timestamp)
2. **Block modification**: when a block on the live volume is about to be overwritten, the **old** data is first copied to a store area
3. **Snapshot reconstruction**: for each block, check if the store has an old copy; if yes, read from the store (pre-modification data); if no, read from the live volume (unchanged since snapshot)

### On-disk structures

| Structure | Location | Size | Description |
|-----------|----------|------|-------------|
| Volume Header | Offset `0x1E00` from partition start | 128 bytes | VSS signature GUID, catalog offset, volume GUID |
| Catalog | Linked list starting at catalog offset | 16 KiB blocks | Store metadata (type 0x02) and locations (type 0x03) |
| Block Descriptors | Linked list per store | 32 bytes each | Maps `original_offset` to `store_data_offset` |
| Store Data | Scattered across volume | 16 KiB blocks | Copy-on-write data for modified blocks |

Format specification: [libvshadow documentation](https://github.com/libyal/libvshadow/blob/main/documentation/Volume%20Shadow%20Snapshot%20(VSS)%20format.asciidoc) by Joachim Metz.

## License

Dual-licensed under MIT and Apache 2.0.

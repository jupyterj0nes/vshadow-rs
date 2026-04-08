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

## Why?

During incident response, attackers frequently clear Windows event logs. But if Volume Shadow Copies exist, the old logs are still there — frozen in time inside the shadow copy snapshots. Existing tools have limitations:

- **vshadowmount** requires FUSE and only works on Linux
- **EVTXECmd --vss** requires the Windows VSS COM API and only works on live systems
- **Neither** can read directly from E01 forensic images

**vshadow-rs** reads the VSS on-disk format directly, giving you cross-platform access to shadow copy data from any forensic image format.

## Install

### As a library

```toml
[dependencies]
vshadow = "0.1"
```

### As a CLI tool

```bash
cargo install vshadow
```

Or download prebuilt binaries from the [Releases page](https://github.com/jupyterj0nes/vshadow-rs/releases).

## CLI Usage

### Inspect VSS stores in a forensic image

```bash
# E01 image (auto-detects partitions via GPT/MBR)
vshadow-info -f evidence.E01

# Raw/dd image
vshadow-info -f disk.dd

# Specify partition offset manually
vshadow-info -f evidence.E01 --offset 0x26700000
```

### Example output

```
vshadow-info v0.1.0
Inspecting: evidence.E01

Format: E01 (Expert Witness Format)
Image size: 476.94 GB

Searching for NTFS partitions...
Found 2 NTFS partition(s)

=== Partition 1 (offset 0x100000, 0.00 GB) ===
  No VSS signature found (System Protection may be disabled)

=== Partition 2 (offset 0x26700000, 0.60 GB) ===
  3 Volume Shadow Copy snapshot(s) found!

  Store 0:
    GUID:          a1b2c3d4-e5f6-7890-abcd-ef1234567890
    Volume size:   475.00 GB
    Creation time: ~19150 days since epoch, 14:23:01 UTC
    Sequence:      1

  Store 1:
    GUID:          b2c3d4e5-f6a7-8901-bcde-f12345678901
    Volume size:   475.00 GB
    Creation time: ~19155 days since epoch, 09:15:30 UTC
    Sequence:      2
```

## Library Usage

```rust
use std::fs::File;
use std::io::BufReader;
use vshadow::VssVolume;

// Open any Read+Seek source
let f = File::open("partition.raw")?;
let mut reader = BufReader::new(f);

// Parse VSS structures
let volume = VssVolume::new(&mut reader)?;
println!("Found {} VSS snapshots", volume.store_count());

for i in 0..volume.store_count() {
    let info = volume.store_info(i)?;
    println!("Store {}: sequence {}", i, info.sequence);

    // Get a reader for this snapshot — implements Read + Seek
    let mut store_reader = volume.store_reader(&mut reader, i)?;

    // Pass to any filesystem parser (e.g., ntfs crate)
    // let ntfs = ntfs::Ntfs::new(&mut store_reader)?;
}
```

### Integration with forensic crates

```rust
// E01 image -> NTFS partition -> VSS stores -> NTFS -> EVTX files
let ewf_reader = ewf::EwfReader::open("evidence.E01")?;
let mut partition = OffsetReader::new(ewf_reader, partition_offset);

let vss = VssVolume::new(&mut partition)?;
for i in 0..vss.store_count() {
    let mut store = vss.store_reader(&mut partition, i)?;
    let ntfs = ntfs::Ntfs::new(&mut store)?;
    // Navigate to Windows\System32\winevt\Logs\
    // Extract EVTX files from the snapshot...
}
```

## How it works

VSS uses a copy-on-write mechanism:

1. When a snapshot is created, the current state of every block is recorded in the catalog
2. When a block is later modified on the live volume, the **old** data is copied to a store area before the write
3. To reconstruct the snapshot: read from the store area for changed blocks, and from the current volume for unchanged blocks

vshadow-rs parses these on-disk structures:

| Structure | Location | Description |
|-----------|----------|-------------|
| Volume Header | Offset `0x1E00` | VSS signature, catalog offset, volume GUID |
| Catalog | Linked list of 16 KiB blocks | Store metadata (GUID, creation time) and locations |
| Block Descriptors | 32 bytes each | Map original_offset to store_data_offset |
| Store Reader | Computed | Overlays block descriptors on base volume for snapshot view |

## Supported formats

| Image format | Support |
|-------------|---------|
| E01 (Expert Witness Format) | Via `ewf` crate |
| Raw/dd | Native `std::fs::File` |
| VMDK, VHD, QCOW2 | Any crate that provides `Read + Seek` |
| Partition images | Direct (offset = 0) |

## Supported Windows versions

VSS v1 (Vista, 7, Server 2008/2008R2) and VSS v2 (8, 10, 11, Server 2012-2022).

## Part of the WIA project

vshadow-rs is part of [We Investigate Anything](https://weinvestigateanything.com) and is used by [masstin](https://github.com/jupyterj0nes/masstin) for forensic image analysis with VSS support.

## License

Dual-licensed under MIT and Apache 2.0.

## Credits

VSS format specification based on the [libvshadow documentation](https://github.com/libyal/libvshadow/blob/main/documentation/Volume%20Shadow%20Snapshot%20(VSS)%20format.asciidoc) by Joachim Metz.

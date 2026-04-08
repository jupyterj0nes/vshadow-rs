# vshadow-rs

<div align="center">
  <strong>Pure Rust parser for Windows Volume Shadow Copy (VSS) snapshots</strong>
  <br><br>

  [![License](https://img.shields.io/badge/License-MIT%2FApache--2.0-blue.svg)]()
  [![Rust](https://img.shields.io/badge/Rust-000000?logo=rust&logoColor=white)](https://www.rust-lang.org/)
  [![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)]()

</div>

---

Read-only access to Windows Volume Shadow Copy (VSS) snapshots from any `Read + Seek` source — forensic disk images (E01, dd), raw partitions, or mounted volumes. **No Windows APIs required.** Works on Linux, macOS, and Windows.

## Why?

During incident response, attackers frequently clear Windows event logs. But if Volume Shadow Copies exist, the old logs are still there — frozen in time inside the shadow copy snapshots. Tools like `vshadowmount` require FUSE and only work on Linux. EVTXECmd's `--vss` flag requires the Windows VSS COM API and only works on live systems.

**vshadow-rs** reads the VSS on-disk format directly, giving you cross-platform access to shadow copy data from forensic images.

## Usage

```rust
use std::fs::File;
use std::io::BufReader;
use vshadow::VssVolume;

// Open any Read+Seek source (raw partition, E01 via ewf crate, etc.)
let f = File::open("partition.raw")?;
let mut reader = BufReader::new(f);

// Parse VSS structures
let volume = VssVolume::new(&mut reader)?;
println!("Found {} VSS snapshots", volume.store_count());

for i in 0..volume.store_count() {
    let info = volume.store_info(i)?;
    println!("Store {}: {} changed blocks", i, info.volume_size);

    // Get a reader for this snapshot — implements Read + Seek
    let mut store_reader = volume.store_reader(&mut reader, i)?;

    // Pass store_reader to any filesystem parser (e.g., ntfs crate)
    // let ntfs = ntfs::Ntfs::new(&mut store_reader)?;
}
```

## How it works

VSS stores data using a copy-on-write mechanism:

1. When a snapshot is created, the current state of every block is recorded
2. When a block is later modified, the **old** data is copied to a store area
3. To reconstruct the snapshot, read from the store area for changed blocks and from the current volume for unchanged blocks

vshadow-rs parses the on-disk structures:
- **Volume header** at offset `0x1E00` — identifies VSS presence
- **Catalog** — linked list of 16 KiB blocks containing store metadata and locations
- **Block descriptors** — map of which blocks changed and where the old data is stored
- **Store reader** — combines block descriptors with the base volume to present the snapshot view

## Integration with forensic tools

vshadow-rs is designed to integrate with other Rust forensic crates:

```rust
// E01 image → NTFS partition → VSS stores → NTFS filesystem → files
let ewf_reader = ewf::EwfReader::open("evidence.E01")?;
let mut partition = OffsetReader::new(ewf_reader, partition_offset);

let vss = VssVolume::new(&mut partition)?;
for i in 0..vss.store_count() {
    let mut store = vss.store_reader(&mut partition, i)?;
    let ntfs = ntfs::Ntfs::new(&mut store)?;
    // Extract files from the snapshot...
}
```

## VSS Format Reference

Based on the [libvshadow documentation](https://github.com/libyal/libvshadow/blob/main/documentation/Volume%20Shadow%20Snapshot%20(VSS)%20format.asciidoc) by Joachim Metz.

| Structure | Offset | Size | Description |
|-----------|--------|------|-------------|
| Volume Header | 0x1E00 | 128 bytes | VSS signature, catalog offset, volume GUID |
| Catalog Block | variable | 16 KiB | Linked list of store metadata + locations |
| Block Descriptor | variable | 32 bytes | Maps original_offset to store_data_offset |
| Store Data | variable | 16 KiB blocks | Copy-on-write data for changed blocks |

## Supported Windows versions

- Windows Vista / Server 2008 (VSS v1)
- Windows 7 / Server 2008 R2 (VSS v1)
- Windows 8 / Server 2012 (VSS v2)
- Windows 10 / 11 / Server 2016-2022 (VSS v2)

## Part of the WIA project

vshadow-rs is part of the [We Investigate Anything](https://weinvestigateanything.com) (WIA) project and is used by [masstin](https://github.com/jupyterj0nes/masstin) for forensic image analysis with VSS support.

## License

Dual-licensed under MIT and Apache 2.0.

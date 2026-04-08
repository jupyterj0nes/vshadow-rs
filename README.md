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

Inspect, list and extract files from Windows Volume Shadow Copy snapshots inside forensic disk images. **No Windows APIs. No FUSE. No C dependencies. Cross-platform.**

> Part of the [We Investigate Anything](https://weinvestigateanything.com) project.
> Full documentation: [vshadow-rs article](https://weinvestigateanything.com/en/tools/vshadow-rs/) |
> Used by [masstin](https://github.com/jupyterj0nes/masstin) for forensic image analysis.

---

## Why?

Attackers clear Windows event logs. Volume Shadow Copies preserve the old data. But accessing it is painful:

| Tool | Problem |
|------|---------|
| **vshadowmount** | Requires FUSE, Linux only, can't read E01 |
| **EVTXECmd --vss** | Requires Windows VSS COM API, live systems only |

**vshadow-rs** reads the on-disk VSS format directly from any forensic image. One binary, any platform.

---

## Quick Start

```bash
cargo install vshadow
```

```
$ vshadow-info info -f HRServer_Disk0.e01

vshadow-info v0.1.1
Inspecting: HRServer_Disk0.e01

Format: E01 (Expert Witness Format)
Image size: 50.00 GB

Found 1 NTFS partition(s)

=== Partition 1 ===
  Offset:          0x1f500000 (0.49 GB into disk)
  VSS detected:    YES (signature found at partition offset 0x1E00)
  Snapshots:       1

  Store 0:
    GUID:            4479c1da-99b9-11e8-b7f4-acd82990ee82
    Created:         2018-08-07 23:07:58 UTC
    Sequence:        1
    Changed blocks:  9593 (149.9 MB modified since snapshot)
```

---

## CLI Commands

### `info` — Detect VSS stores

```bash
vshadow-info info -f evidence.E01
vshadow-info info -f disk.dd --offset 0x26700000
```

Auto-detects NTFS partitions (GPT + MBR), checks each one for VSS, reports store count, creation date, and how much data changed since the snapshot.

### `list` — Browse files

```bash
# Live volume
vshadow-info list -f evidence.E01 --live -p "Windows/System32/winevt/Logs"

# VSS store (the snapshot — see what was there BEFORE the attacker cleared logs)
vshadow-info list -f evidence.E01 -s 0 -p "Windows/System32/winevt/Logs"
```

### `extract` — Recover files

```bash
# Recover event logs from VSS (deleted from live but preserved in snapshot)
vshadow-info extract -f evidence.E01 -s 0 -p "Windows/System32/winevt/Logs" -o ./recovered/

# Extract from live volume for comparison
vshadow-info extract -f evidence.E01 --live -p "Windows/System32/winevt/Logs" -o ./live/
```

---

## Forensic Workflow

```bash
# 1. Inspect image for shadow copies
vshadow-info info -f suspect.E01

# 2. Compare Security.evtx between live and snapshot
#    (cleared logs = much smaller file on live volume)
vshadow-info list -f suspect.E01 --live -p "Windows/System32/winevt/Logs"
vshadow-info list -f suspect.E01 -s 0 -p "Windows/System32/winevt/Logs"

# 3. Recover the pre-deletion event logs
vshadow-info extract -f suspect.E01 -s 0 -p "Windows/System32/winevt/Logs" -o ./recovered/

# 4. Generate lateral movement timeline with masstin
masstin -a parse-windows -d ./recovered/ -o timeline.csv

# 5. Visualize in Memgraph
masstin -a load-memgraph -f timeline.csv --database localhost:7687
```

---

## Library Usage

```rust
use vshadow::VssVolume;

let mut reader = /* any Read+Seek: File, BufReader, ewf::EwfReader */;
let vss = VssVolume::new(&mut reader)?;

println!("{} snapshots found", vss.store_count());

for i in 0..vss.store_count() {
    let info = vss.store_info(i)?;
    println!("Store {}: created {}", i, info.creation_time_utc());

    let (blocks, delta) = vss.store_delta_size(&mut reader, i)?;
    println!("  {} changed blocks ({} bytes)", blocks, delta);

    // Read+Seek over the snapshot — pass to ntfs crate, etc.
    let mut store = vss.store_reader(&mut reader, i)?;
}
```

---

## Comparison

| Feature | vshadowmount | vshadowinfo | **vshadow-info** |
|---------|:---:|:---:|:---:|
| List VSS stores | - | Yes | **Yes** |
| Show creation dates | - | Yes | **Yes** |
| Show delta size (changed blocks) | - | - | **Yes** |
| Mount as FUSE filesystem | Yes | - | - |
| **List files inside VSS** | via mount | - | **Yes** |
| **Extract files from VSS** | via mount | - | **Yes** |
| **Browse live volume** | - | - | **Yes** |
| **Read E01 directly** | - | - | **Yes** |
| **Auto-detect GPT/MBR** | - | - | **Yes** |
| Cross-platform | Linux | Linux/Mac/Win | **All** |

---

## Supported Formats

| Format | Support |
|--------|---------|
| E01 (Expert Witness Format) | Built-in via `ewf` crate |
| Raw / dd / 001 | Native |
| Partition images | Direct (offset = 0) |

**Windows versions:** Vista through Windows 11, Server 2008 through 2022 (VSS v1 and v2).

---

## How VSS Works

VSS is a **copy-on-write** mechanism at the block level (16 KiB blocks):

1. **Snapshot taken** → catalog records store metadata (GUID, timestamp)
2. **Block modified on live volume** → old data copied to store area first
3. **Reconstruction** → changed blocks read from store, unchanged blocks read from live volume

The delta (changed blocks) tells you how much the disk changed since the snapshot. A small delta means the snapshot is very close to the current state. A large delta means significant changes occurred — possibly including log clearing.

---

## Documentation

| Topic | Link |
|-------|------|
| vshadow-rs full guide | [weinvestigateanything.com — vshadow-rs](https://weinvestigateanything.com/en/tools/vshadow-rs/) |
| masstin (lateral movement analysis) | [weinvestigateanything.com — masstin](https://weinvestigateanything.com/en/tools/masstin-lateral-movement-rust/) |
| Security.evtx forensic artifacts | [weinvestigateanything.com — Security.evtx](https://weinvestigateanything.com/en/artifacts/security-evtx-lateral-movement/) |
| Neo4j graph visualization | [weinvestigateanything.com — Neo4j](https://weinvestigateanything.com/en/tools/neo4j-cypher-visualization/) |
| Memgraph visualization | [weinvestigateanything.com — Memgraph](https://weinvestigateanything.com/en/tools/memgraph-visualization/) |

---

## License

Dual-licensed under MIT and Apache 2.0.

## Credits

VSS format specification: [libvshadow documentation](https://github.com/libyal/libvshadow/blob/main/documentation/Volume%20Shadow%20Snapshot%20(VSS)%20format.asciidoc) by Joachim Metz.

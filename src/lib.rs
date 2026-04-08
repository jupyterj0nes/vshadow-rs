//! # vshadow
//!
//! Pure Rust parser for Windows Volume Shadow Copy (VSS) snapshots.
//!
//! Provides read-only access to VSS stores (shadow copy snapshots) from any
//! `Read + Seek` source — forensic disk images (E01, dd), raw partitions, etc.
//! No Windows APIs required; works on Linux, macOS, and Windows.
//!
//! ## Usage
//!
//! ```no_run
//! use std::fs::File;
//! use std::io::BufReader;
//! use vshadow::VssVolume;
//!
//! let f = File::open("partition.raw")?;
//! let mut reader = BufReader::new(f);
//! let volume = VssVolume::new(&mut reader)?;
//!
//! println!("Found {} VSS snapshots", volume.store_count());
//!
//! for i in 0..volume.store_count() {
//!     let info = volume.store_info(i)?;
//!     println!("Store {}: created {}", i, info.creation_time);
//!
//!     // Create a reader for this VSS store
//!     let mut store_reader = volume.store_reader(&mut reader, i)?;
//!     // store_reader implements Read + Seek — pass it to an NTFS parser
//! }
//! # Ok::<(), vshadow::VssError>(())
//! ```

mod error;
mod header;
mod catalog;
mod store;
mod reader;

pub use error::VssError;
pub use header::VssVolumeHeader;
pub use catalog::{CatalogEntry, StoreMeta, StoreLocation};
pub use store::StoreInfo;
pub use reader::VssStoreReader;

use std::io::{Read, Seek, SeekFrom};
use std::collections::HashMap;

/// VSS magic identifier GUID: {6B87080 ...}
const VSS_HEADER_OFFSET: u64 = 0x1E00;
const CATALOG_BLOCK_SIZE: usize = 0x4000; // 16 KiB
const BLOCK_SIZE: u64 = 0x4000; // 16 KiB

/// Represents a VSS-enabled volume with zero or more shadow copy stores.
pub struct VssVolume {
    pub header: VssVolumeHeader,
    pub stores: Vec<(StoreMeta, StoreLocation)>,
}

impl VssVolume {
    /// Parse VSS structures from a volume.
    /// The reader should be positioned at the start of the NTFS partition.
    pub fn new<R: Read + Seek>(reader: &mut R) -> Result<Self, VssError> {
        // Read volume header at offset 0x1E00
        reader.seek(SeekFrom::Start(VSS_HEADER_OFFSET))
            .map_err(|e| VssError::Io(e))?;

        let header = VssVolumeHeader::parse(reader)?;

        if header.catalog_offset == 0 {
            return Ok(Self {
                header,
                stores: Vec::new(),
            });
        }

        // Parse catalog
        let entries = catalog::parse_catalog(reader, header.catalog_offset)?;

        // Match store metadata (type 0x02) with store locations (type 0x03) by GUID
        let mut meta_map: HashMap<[u8; 16], StoreMeta> = HashMap::new();
        let mut loc_map: HashMap<[u8; 16], StoreLocation> = HashMap::new();

        for entry in entries {
            match entry {
                CatalogEntry::Meta(m) => { meta_map.insert(m.store_id, m); }
                CatalogEntry::Location(l) => { loc_map.insert(l.store_id, l); }
                CatalogEntry::Empty => {}
            }
        }

        let mut stores: Vec<(StoreMeta, StoreLocation)> = Vec::new();
        for (guid, meta) in &meta_map {
            if let Some(loc) = loc_map.get(guid) {
                stores.push((meta.clone(), loc.clone()));
            }
        }

        // Sort by creation time (oldest first)
        stores.sort_by_key(|(m, _)| m.creation_time);

        // Update volume_size from store metadata (header doesn't contain it)
        let mut hdr = header;
        if let Some((meta, _)) = stores.first() {
            if meta.volume_size > 0 {
                hdr.volume_size = meta.volume_size;
            }
        }

        Ok(Self { header: hdr, stores })
    }

    /// Number of VSS stores (snapshots) found.
    pub fn store_count(&self) -> usize {
        self.stores.len()
    }

    /// Get metadata for a specific store.
    pub fn store_info(&self, index: usize) -> Result<StoreInfo, VssError> {
        let (meta, loc) = self.stores.get(index)
            .ok_or(VssError::InvalidStoreIndex(index))?;
        Ok(StoreInfo::from_meta_and_location(meta, loc))
    }

    /// Count changed blocks in a store. Returns (block_count, delta_size_bytes).
    pub fn store_delta_size<R: Read + Seek>(
        &self,
        reader: &mut R,
        index: usize,
    ) -> Result<(usize, u64), VssError> {
        let (_, loc) = self.stores.get(index)
            .ok_or(VssError::InvalidStoreIndex(index))?;
        let block_map = store::parse_block_descriptors(reader, loc.block_list_offset)?;
        let count = block_map.len();
        let size = count as u64 * BLOCK_SIZE;
        Ok((count, size))
    }

    /// Create a reader for a specific VSS store.
    /// The returned reader implements Read + Seek and presents the volume
    /// as it appeared at the time of the snapshot.
    pub fn store_reader<'a, R: Read + Seek>(
        &'a self,
        reader: &'a mut R,
        index: usize,
    ) -> Result<VssStoreReader<'a, R>, VssError> {
        let (_, loc) = self.stores.get(index)
            .ok_or(VssError::InvalidStoreIndex(index))?;

        // Parse block descriptors for this store
        let block_map = store::parse_block_descriptors(reader, loc.block_list_offset)?;

        Ok(VssStoreReader::new(reader, block_map, self.header.volume_size))
    }
}

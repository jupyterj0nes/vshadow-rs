use std::io::{Read, Seek, SeekFrom};
use crate::VssError;

const CATALOG_BLOCK_SIZE: usize = 0x4000; // 16 KiB
const ENTRY_SIZE: usize = 128;
const HEADER_SIZE: usize = 128;

/// A parsed catalog entry.
#[derive(Debug, Clone)]
pub enum CatalogEntry {
    /// Type 0x02: Shadow copy metadata
    Meta(StoreMeta),
    /// Type 0x03: Store location data
    Location(StoreLocation),
    /// Empty or unknown entry
    Empty,
}

/// Shadow copy metadata (catalog entry type 0x02).
#[derive(Debug, Clone)]
pub struct StoreMeta {
    /// Volume size at time of snapshot
    pub volume_size: u64,
    /// Store identifier GUID (matches StoreLocation)
    pub store_id: [u8; 16],
    /// Sequence number
    pub sequence: u64,
    /// Flags
    pub flags: u64,
    /// Creation time (Windows FILETIME: 100ns intervals since 1601-01-01 UTC)
    pub creation_time: u64,
}

/// Store location data (catalog entry type 0x03).
#[derive(Debug, Clone)]
pub struct StoreLocation {
    /// Store block list offset (block descriptors)
    pub block_list_offset: u64,
    /// Store identifier GUID (matches StoreMeta)
    pub store_id: [u8; 16],
    /// Store header offset
    pub store_header_offset: u64,
    /// Store block range list offset
    pub block_range_list_offset: u64,
    /// Store bitmap offset
    pub bitmap_offset: u64,
}

/// Parse the entire VSS catalog by following the linked list of 16 KiB blocks.
pub fn parse_catalog<R: Read + Seek>(
    reader: &mut R,
    first_block_offset: u64,
) -> Result<Vec<CatalogEntry>, VssError> {
    let mut entries = Vec::new();
    let mut current_offset = first_block_offset;

    loop {
        if current_offset == 0 {
            break;
        }

        reader.seek(SeekFrom::Start(current_offset))
            .map_err(VssError::Io)?;

        let mut block = vec![0u8; CATALOG_BLOCK_SIZE];
        reader.read_exact(&mut block).map_err(VssError::Io)?;

        // Parse block header (first 128 bytes)
        let record_type = u32::from_le_bytes(block[20..24].try_into().unwrap());
        if record_type != 0x02 {
            // Not a catalog block
            break;
        }

        let next_offset = u64::from_le_bytes(block[40..48].try_into().unwrap());

        // Parse entries after the header
        let mut pos = HEADER_SIZE;
        while pos + ENTRY_SIZE <= CATALOG_BLOCK_SIZE {
            let entry_data = &block[pos..pos + ENTRY_SIZE];
            let entry_type = u64::from_le_bytes(entry_data[0..8].try_into().unwrap());

            match entry_type {
                0x02 => {
                    entries.push(CatalogEntry::Meta(StoreMeta {
                        volume_size: u64::from_le_bytes(entry_data[8..16].try_into().unwrap()),
                        store_id: entry_data[16..32].try_into().unwrap(),
                        sequence: u64::from_le_bytes(entry_data[32..40].try_into().unwrap()),
                        flags: u64::from_le_bytes(entry_data[40..48].try_into().unwrap()),
                        creation_time: u64::from_le_bytes(entry_data[48..56].try_into().unwrap()),
                    }));
                }
                0x03 => {
                    entries.push(CatalogEntry::Location(StoreLocation {
                        block_list_offset: u64::from_le_bytes(entry_data[8..16].try_into().unwrap()),
                        store_id: entry_data[16..32].try_into().unwrap(),
                        store_header_offset: u64::from_le_bytes(entry_data[32..40].try_into().unwrap()),
                        block_range_list_offset: u64::from_le_bytes(entry_data[40..48].try_into().unwrap()),
                        bitmap_offset: u64::from_le_bytes(entry_data[48..56].try_into().unwrap()),
                    }));
                }
                0x00 => {
                    // Empty entry — end of entries in this block
                    break;
                }
                _ => {
                    entries.push(CatalogEntry::Empty);
                }
            }

            pos += ENTRY_SIZE;
        }

        current_offset = next_offset;
    }

    Ok(entries)
}

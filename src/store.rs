use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom};
use crate::catalog::{StoreMeta, StoreLocation};
use crate::VssError;

const BLOCK_SIZE: u64 = 0x4000; // 16 KiB
const BLOCK_HEADER_SIZE: usize = 128;
const DESCRIPTOR_SIZE: usize = 32;

/// High-level store information.
#[derive(Debug, Clone)]
pub struct StoreInfo {
    /// Store GUID
    pub store_id: [u8; 16],
    /// Volume size at snapshot time
    pub volume_size: u64,
    /// Creation time (Windows FILETIME)
    pub creation_time: u64,
    /// Sequence number
    pub sequence: u64,
    /// Block list offset
    pub block_list_offset: u64,
    /// Store header offset
    pub store_header_offset: u64,
}

impl StoreInfo {
    pub fn from_meta_and_location(meta: &StoreMeta, loc: &StoreLocation) -> Self {
        Self {
            store_id: meta.store_id,
            volume_size: meta.volume_size,
            creation_time: meta.creation_time,
            sequence: meta.sequence,
            block_list_offset: loc.block_list_offset,
            store_header_offset: loc.store_header_offset,
        }
    }

    /// Convert FILETIME to a human-readable UTC string.
    pub fn creation_time_utc(&self) -> String {
        // FILETIME: 100-nanosecond intervals since 1601-01-01
        // Unix epoch offset: 11644473600 seconds
        let secs_since_1601 = self.creation_time / 10_000_000;
        let unix_secs = secs_since_1601.saturating_sub(11_644_473_600);
        // Simple UTC format without chrono dependency
        let days = unix_secs / 86400;
        let time_of_day = unix_secs % 86400;
        let hours = time_of_day / 3600;
        let minutes = (time_of_day % 3600) / 60;
        let seconds = time_of_day % 60;
        // Rough date calculation (good enough for display)
        format!("~{} days since epoch, {:02}:{:02}:{:02} UTC", days, hours, minutes, seconds)
    }
}

/// A block descriptor mapping: original_offset -> store_data_offset
#[derive(Debug, Clone)]
pub struct BlockDescriptor {
    /// Offset of the original data block on the volume
    pub original_offset: u64,
    /// Offset of the stored (old) data block on the volume
    pub store_data_offset: u64,
    /// Flags
    pub flags: u32,
}

/// Parse block descriptors for a store.
/// Returns a BTreeMap from original_offset -> store_data_offset.
/// This map tells us: "to read what was at original_offset at snapshot time,
/// read from store_data_offset instead."
pub fn parse_block_descriptors<R: Read + Seek>(
    reader: &mut R,
    first_block_offset: u64,
) -> Result<BTreeMap<u64, BlockDescriptor>, VssError> {
    let mut map = BTreeMap::new();
    let mut current_offset = first_block_offset;

    loop {
        if current_offset == 0 {
            break;
        }

        reader.seek(SeekFrom::Start(current_offset))
            .map_err(VssError::Io)?;

        let mut block = vec![0u8; BLOCK_SIZE as usize];
        reader.read_exact(&mut block).map_err(VssError::Io)?;

        // Parse block header
        let record_type = u32::from_le_bytes(block[20..24].try_into().unwrap());
        if record_type != 0x03 {
            break;
        }

        let next_offset = u64::from_le_bytes(block[40..48].try_into().unwrap());

        // Parse descriptors after the header
        let mut pos = BLOCK_HEADER_SIZE;
        while pos + DESCRIPTOR_SIZE <= BLOCK_SIZE as usize {
            let desc = &block[pos..pos + DESCRIPTOR_SIZE];

            let original_offset = u64::from_le_bytes(desc[0..8].try_into().unwrap());
            let _relative_offset = u64::from_le_bytes(desc[8..16].try_into().unwrap());
            let store_data_offset = u64::from_le_bytes(desc[16..24].try_into().unwrap());
            let flags = u32::from_le_bytes(desc[24..28].try_into().unwrap());

            // Skip empty or "not used" descriptors
            if original_offset == 0 && store_data_offset == 0 {
                break;
            }
            if flags & 0x04 != 0 {
                // "Not used" flag
                pos += DESCRIPTOR_SIZE;
                continue;
            }

            map.insert(original_offset, BlockDescriptor {
                original_offset,
                store_data_offset,
                flags,
            });

            pos += DESCRIPTOR_SIZE;
        }

        current_offset = next_offset;
    }

    Ok(map)
}

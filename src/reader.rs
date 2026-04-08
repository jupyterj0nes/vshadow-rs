use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom, Result as IoResult};
use crate::store::BlockDescriptor;

const BLOCK_SIZE: u64 = 0x4000; // 16 KiB

/// A reader that presents a VSS store as a seekable byte stream.
///
/// When reading, it checks the block descriptor map:
/// - If the block was changed after the snapshot, it reads from the stored
///   (old) copy at store_data_offset — this is what the block looked like
///   at snapshot time.
/// - If the block was NOT changed, it reads from the current volume directly
///   — meaning the block is the same as at snapshot time.
pub struct VssStoreReader<'a, R: Read + Seek> {
    inner: &'a mut R,
    block_map: BTreeMap<u64, BlockDescriptor>,
    volume_size: u64,
    position: u64,
}

impl<'a, R: Read + Seek> VssStoreReader<'a, R> {
    pub fn new(
        inner: &'a mut R,
        block_map: BTreeMap<u64, BlockDescriptor>,
        volume_size: u64,
    ) -> Self {
        Self {
            inner,
            block_map,
            volume_size,
            position: 0,
        }
    }

    /// Number of block descriptors (changed blocks).
    pub fn changed_block_count(&self) -> usize {
        self.block_map.len()
    }

    /// Resolve where to read a given offset from.
    /// Returns the actual offset on the volume to read from.
    fn resolve_offset(&self, offset: u64) -> u64 {
        // Align to block boundary
        let block_start = (offset / BLOCK_SIZE) * BLOCK_SIZE;

        if let Some(desc) = self.block_map.get(&block_start) {
            // This block was changed AFTER the snapshot.
            // The OLD data (snapshot-time data) is at store_data_offset.
            let offset_within_block = offset - block_start;
            desc.store_data_offset + offset_within_block
        } else {
            // Block was NOT changed — current volume data IS the snapshot data.
            offset
        }
    }
}

impl<'a, R: Read + Seek> Read for VssStoreReader<'a, R> {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        if self.position >= self.volume_size {
            return Ok(0);
        }

        let remaining = (self.volume_size - self.position) as usize;
        let to_read = buf.len().min(remaining);

        if to_read == 0 {
            return Ok(0);
        }

        // Read block-by-block to handle block boundary crossings
        let block_start = (self.position / BLOCK_SIZE) * BLOCK_SIZE;
        let offset_in_block = (self.position - block_start) as usize;
        let bytes_left_in_block = BLOCK_SIZE as usize - offset_in_block;
        let chunk_size = to_read.min(bytes_left_in_block);

        let actual_offset = self.resolve_offset(self.position);
        self.inner.seek(SeekFrom::Start(actual_offset))?;
        let bytes_read = self.inner.read(&mut buf[..chunk_size])?;

        self.position += bytes_read as u64;
        Ok(bytes_read)
    }
}

impl<'a, R: Read + Seek> Seek for VssStoreReader<'a, R> {
    fn seek(&mut self, pos: SeekFrom) -> IoResult<u64> {
        self.position = match pos {
            SeekFrom::Start(p) => p,
            SeekFrom::Current(p) => {
                if p >= 0 {
                    self.position + p as u64
                } else {
                    self.position.saturating_sub((-p) as u64)
                }
            }
            SeekFrom::End(p) => {
                if p >= 0 {
                    self.volume_size
                } else {
                    self.volume_size.saturating_sub((-p) as u64)
                }
            }
        };
        Ok(self.position)
    }
}

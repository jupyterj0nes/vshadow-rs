use std::io::{Read, Seek};
use crate::VssError;

/// VSS Volume Header — located at offset 0x1E00 from partition start.
#[derive(Debug, Clone)]
pub struct VssVolumeHeader {
    /// VSS identifier GUID
    pub vss_id: [u8; 16],
    /// Version: 1 = Vista/7, 2 = Windows 8+
    pub version: u32,
    /// Record type (should be 0x01)
    pub record_type: u32,
    /// Offset of the catalog (0 if no VSS snapshots exist)
    pub catalog_offset: u64,
    /// Maximum VSS storage size (0 = unbounded)
    pub max_size: u64,
    /// Volume identifier GUID
    pub volume_id: [u8; 16],
    /// Shadow copy storage volume GUID
    pub storage_volume_id: [u8; 16],
    /// Volume size (used for store reader bounds)
    pub volume_size: u64,
}

/// Known VSS identifier GUID: {6B87080 ...} in mixed-endian
const VSS_GUID_BYTES: [u8; 16] = [
    0x6B, 0x87, 0x08, 0x38, 0x76, 0xB1, 0x48, 0x42,
    0xB7, 0xD5, 0xCE, 0xB9, 0xC0, 0x86, 0x74, 0x7A,
];

impl VssVolumeHeader {
    pub fn parse<R: Read + Seek>(reader: &mut R) -> Result<Self, VssError> {
        let mut buf = [0u8; 128];
        reader.read_exact(&mut buf).map_err(VssError::Io)?;

        // Verify VSS signature
        let vss_id: [u8; 16] = buf[0..16].try_into().unwrap();
        if vss_id != VSS_GUID_BYTES {
            return Err(VssError::InvalidSignature);
        }

        let version = u32::from_le_bytes(buf[16..20].try_into().unwrap());
        let record_type = u32::from_le_bytes(buf[20..24].try_into().unwrap());
        let catalog_offset = u64::from_le_bytes(buf[48..56].try_into().unwrap());
        let max_size = u64::from_le_bytes(buf[56..64].try_into().unwrap());
        let volume_id: [u8; 16] = buf[64..80].try_into().unwrap();
        let storage_volume_id: [u8; 16] = buf[80..96].try_into().unwrap();

        // Volume size is not directly in the header; we'll get it from store metadata.
        // For now set to 0 — will be updated when stores are parsed.
        Ok(Self {
            vss_id,
            version,
            record_type,
            catalog_offset,
            max_size,
            volume_id,
            storage_volume_id,
            volume_size: 0,
        })
    }
}

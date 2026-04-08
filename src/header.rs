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

/// Known VSS identifier GUID: {6B870838-76B1-4842-B7D5-CEB9C086747A}
/// On disk, GUIDs are stored in mixed-endian format:
/// - Data1 (4 bytes): little-endian
/// - Data2 (2 bytes): little-endian
/// - Data3 (2 bytes): little-endian
/// - Data4 (8 bytes): big-endian (as-is)
///
/// However, the VSS identifier at offset 0x1E00 is a volume-specific GUID,
/// NOT the fixed VSS GUID. We identify VSS by checking the record_type field
/// (bytes 20-24) which should be 0x00000001 for a VSS volume header,
/// AND verifying the first 4 bytes match 0x6B870838 in either endian form.
const VSS_MAGIC_LE: [u8; 4] = [0x38, 0x08, 0x87, 0x6B]; // LE form
const VSS_MAGIC_BE: [u8; 4] = [0x6B, 0x87, 0x08, 0x38]; // BE/canonical form

impl VssVolumeHeader {
    pub fn parse<R: Read + Seek>(reader: &mut R) -> Result<Self, VssError> {
        let mut buf = [0u8; 128];
        reader.read_exact(&mut buf).map_err(VssError::Io)?;

        // Verify VSS signature: check first 4 bytes of GUID + record_type
        let first4: [u8; 4] = buf[0..4].try_into().unwrap();
        let record_type = u32::from_le_bytes(buf[20..24].try_into().unwrap());

        #[cfg(debug_assertions)]
        {
            eprintln!("[VSS DEBUG] First 4 bytes: {:02X?}, record_type: {:#x}", &first4, record_type);
        }

        let is_vss = (first4 == VSS_MAGIC_LE || first4 == VSS_MAGIC_BE) && record_type == 0x01;
        if !is_vss {
            return Err(VssError::InvalidSignature);
        }

        let vss_id: [u8; 16] = buf[0..16].try_into().unwrap();

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

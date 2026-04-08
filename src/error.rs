use std::fmt;
use std::io;

#[derive(Debug)]
pub enum VssError {
    /// I/O error reading from the volume.
    Io(io::Error),
    /// The VSS header signature is invalid — no VSS on this volume.
    InvalidSignature,
    /// Unsupported VSS version.
    UnsupportedVersion(u32),
    /// Invalid catalog block structure.
    InvalidCatalog(String),
    /// Store index out of range.
    InvalidStoreIndex(usize),
    /// Error parsing block descriptors.
    BlockDescriptorError(String),
}

impl fmt::Display for VssError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {}", e),
            Self::InvalidSignature => write!(f, "No VSS signature found at offset 0x1E00"),
            Self::UnsupportedVersion(v) => write!(f, "Unsupported VSS version: {}", v),
            Self::InvalidCatalog(msg) => write!(f, "Invalid VSS catalog: {}", msg),
            Self::InvalidStoreIndex(i) => write!(f, "VSS store index {} out of range", i),
            Self::BlockDescriptorError(msg) => write!(f, "Block descriptor error: {}", msg),
        }
    }
}

impl std::error::Error for VssError {}

impl From<io::Error> for VssError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

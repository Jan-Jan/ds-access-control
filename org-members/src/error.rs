use alloc::string::String;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OrgMembersError {
    #[error("duplicate handle")]
    DuplicateHandle,

    #[error("duplicate member id")]
    DuplicateId,

    #[error("member id not found")]
    IdNotFound,

    #[error("invalid handle: {0}")]
    InvalidHandle(String),

    #[error("confusable handle")]
    ConfusableHandle,

    #[error("duplicate device")]
    DuplicateDevice,

    #[error("device not found")]
    DeviceNotFound,

    #[error("device slots full (max 4)")]
    DeviceSlotsFull,

    #[error("member must have at least one device")]
    EmptyDeviceList,

    #[error("delta base root mismatch")]
    DeltaBaseMismatch,

    #[error("verification failed")]
    VerificationFailed,

    #[error("serialization error")]
    SerializationError,

    #[error("hashes not calculated")]
    HashesNotCalculated,

    #[error("internal invariant violated")]
    InvariantViolated,

    #[error("malformed delta: {0}")]
    MalformedDelta(&'static str),

    #[error("field too long: {field} exceeds {max} bytes after NFC normalization")]
    FieldTooLong { field: &'static str, max: usize },
}

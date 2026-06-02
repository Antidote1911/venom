use zeroize::ZeroizeOnDrop;

/// 256-bit master key — zeroized on drop
#[derive(Clone, ZeroizeOnDrop)]
pub struct MasterKey([u8; 32]);

impl MasterKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MasterKey([REDACTED])")
    }
}

/// Key derived from password+salt via Argon2id — zeroized on drop
#[derive(Clone, ZeroizeOnDrop)]
pub struct DerivedKey(Vec<u8>);

impl DerivedKey {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn as_array_32(&self) -> Option<[u8; 32]> {
        if self.0.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&self.0);
            Some(arr)
        } else {
            None
        }
    }
}

impl std::fmt::Debug for DerivedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DerivedKey([REDACTED])")
    }
}

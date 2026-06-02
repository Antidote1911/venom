/// The on-disk layout of a single encrypted block file.
///
/// Layout (all little-endian):
///   [0..4]   magic   "VNMB"
///   [4..8]   version u32
///   [8..20]  nonce   12 bytes
///   [20..]   ciphertext + 16-byte Poly1305/GCM tag
///
/// The AAD (additional authenticated data) used during encryption is the
/// block UUID as raw bytes, binding the ciphertext to its identity and
/// preventing block swapping attacks.
pub struct VaultHeader;

impl VaultHeader {
    pub const MAGIC: &'static [u8; 4] = b"VNMB";
    pub const VERSION: u32 = 1;
    pub const NONCE_OFFSET: usize = 8;
    pub const NONCE_LEN: usize = 12;
    pub const HEADER_LEN: usize = 20; // magic(4) + version(4) + nonce(12)
}

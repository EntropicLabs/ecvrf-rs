use curve25519_dalek::{
    constants::ED25519_BASEPOINT_TABLE, edwards::CompressedEdwardsY, scalar::Scalar,
};
use sha2::{Digest, Sha512};

pub struct SecretKey {
    bytes: [u8; 32],
}

pub struct PublicKey {
    point: CompressedEdwardsY,
}

impl SecretKey {
    pub fn new(bytes: &[u8; 32]) -> Self {
        SecretKey { bytes: *bytes }
    }
    pub fn from_slice(bytes: &[u8]) -> Self {
        let mut b = [0u8; 32];
        b.copy_from_slice(&bytes);
        SecretKey { bytes: b }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn to_bytes(&self) -> [u8; 32] {
        self.bytes
    }
    pub fn extract_public_key_and_scalar(&self) -> (PublicKey, Scalar) {
        let mut hasher = Sha512::new();
        hasher.update(&self.bytes);
        let hash: [u8; 64] = hasher.finalize().into();
        let mut digest: [u8; 32] = [0u8; 32];
        digest.copy_from_slice(&hash[..32]);
        digest[0] &= 0xF8;
        digest[31] &= 0x7F;
        digest[31] |= 0x40;

        let scalar = Scalar::from_bits(digest);

        let point = &scalar * &ED25519_BASEPOINT_TABLE;
        let pk = PublicKey {
            point: point.compress(),
        };
        (pk, scalar)
    }
}

impl AsRef<[u8]> for SecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl PublicKey {
    pub fn new(point: CompressedEdwardsY) -> Self {
        PublicKey { point }
    }
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut b = [0u8; 32];
        b.copy_from_slice(&bytes);
        PublicKey {
            point: CompressedEdwardsY::from_slice(&b),
        }
    }
    pub fn as_bytes(&self) -> &[u8] {
        self.point.as_bytes()
    }
    pub fn to_bytes(&self) -> [u8; 32] {
        self.point.to_bytes()
    }
    pub fn as_point(&self) -> &CompressedEdwardsY {
        &self.point
    }
}

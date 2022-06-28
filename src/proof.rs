use crate::{
    errors::VRFError,
    keys::{PublicKey, SecretKey},
    utils::{prove, verify_proof},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    pub signer: PublicKey,
    pub message_bytes: Vec<u8>,
    pub proof_bytes: Vec<u8>,
}

impl Proof {
    pub fn new(secret_key: &SecretKey, message: impl AsRef<[u8]>) -> Result<Self, VRFError> {
        prove(secret_key, message.as_ref())
    }

    pub fn verify(&self) -> Result<[u8; 64], VRFError> {
        verify_proof(self)
    }
}
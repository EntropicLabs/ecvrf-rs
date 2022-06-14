use crate::keys::PublicKey;

pub struct Proof{
    pub proof_bytes: Vec<u8>,
    pub signer: PublicKey,
    pub message_bytes: Vec<u8>,
}
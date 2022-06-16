use thiserror::Error;

#[derive(Debug, Error)]
pub enum VRFError {
    #[error("Invalid secret key")]
    InvalidSecretKey {},
    
    #[error("Invalid public key")]
    InvalidPublicKey {},

    #[error("Invalid proof")]
    InvalidProof {},

    #[error("Error decoding proof")]
    DecodeProofError {},
}

use schemars::JsonSchema;
use serde::{Serialize, Deserialize};

use crate::{
    errors::VRFError,
    keys::{PublicKey, SecretKey},
    utils::{prove, verify_proof},
};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct Proof {
    pub proof_bytes: Vec<u8>,
    pub signer: PublicKey,
    pub message_bytes: Vec<u8>,
}

impl Proof {
    pub fn new(secret_key: &SecretKey, message: impl AsRef<[u8]>) -> Result<Self, VRFError> {
        prove(secret_key, message.as_ref())
    }

    pub fn verify(&self) -> Result<[u8; 64], VRFError> {
        verify_proof(self)
    }
}
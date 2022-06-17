use curve25519_dalek::{
    constants::ED25519_BASEPOINT_TABLE, edwards::CompressedEdwardsY, scalar::Scalar,
};

use schemars::{
    gen::SchemaGenerator,
    schema::{InstanceType, Schema, SchemaObject},
    JsonSchema,
};
use serde::{de::Error, Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha512};

use crate::errors::VRFError;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct SecretKey {
    #[serde(
        serialize_with = "hex::serde::serialize",
        deserialize_with = "hex::serde::deserialize"
    )]
    bytes: [u8; 32],
}

impl JsonSchema for SecretKey {
    fn schema_name() -> String {
        "SecretKey".to_owned()
    }
    fn json_schema(gen: &mut SchemaGenerator) -> Schema {
        let mut schema_object = SchemaObject {
            instance_type: Some(InstanceType::Object.into()),
            ..Default::default()
        };
        let object_validation = schema_object.object();

        let mut fixed_size_string = gen.subschema_for::<String>();
        if let Schema::Object(schema_object) = &mut fixed_size_string {
            let validation = schema_object.string();
            validation.min_length = Some(64u32);
            validation.max_length = Some(64u32);
        }
        object_validation
            .properties
            .insert("bytes".to_owned(), fixed_size_string);
        object_validation.required.insert("bytes".to_owned());
        Schema::Object(schema_object)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct PublicKey {
    #[serde(
        serialize_with = "hex::serde::serialize",
        deserialize_with = "from_hex",
        rename = "bytes"
    )]
    point: CompressedEdwardsY,
}

impl JsonSchema for PublicKey {
    fn schema_name() -> String {
        "PublicKey".to_owned()
    }
    fn json_schema(gen: &mut SchemaGenerator) -> Schema {
        let mut schema_object = SchemaObject {
            instance_type: Some(InstanceType::Object.into()),
            ..Default::default()
        };
        let object_validation = schema_object.object();

        let mut fixed_size_string = gen.subschema_for::<String>();
        if let Schema::Object(schema_object) = &mut fixed_size_string {
            let validation = schema_object.string();
            validation.min_length = Some(64u32);
            validation.max_length = Some(64u32);
        }
        object_validation
            .properties
            .insert("bytes".to_owned(), fixed_size_string);
        object_validation.required.insert("bytes".to_owned());
        Schema::Object(schema_object)
    }
}

fn from_hex<'de, D>(deserializer: D) -> Result<CompressedEdwardsY, D::Error>
where
    D: Deserializer<'de>,
{
    let s: &str = Deserialize::deserialize(deserializer)?;
    // do better hex decoding than this
    Ok(CompressedEdwardsY::from_slice(
        hex::decode(s)
            .map_err(|_| D::Error::custom("Invalid hex string"))?
            .as_slice(),
    ))
}

impl SecretKey {
    pub fn new(bytes: &[u8; 32]) -> Self {
        SecretKey { bytes: *bytes }
    }
    pub fn from_slice(bytes: &[u8]) -> Self {
        let mut b = [0u8; 32];
        b.copy_from_slice(bytes);
        SecretKey { bytes: b }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.bytes
    }

    pub fn extract_public_key_and_scalar(&self) -> Result<(PublicKey, Scalar), VRFError> {
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
        if point.mul_by_cofactor().compress() == CompressedEdwardsY::default() {
            return Err(VRFError::InvalidSecretKey {});
        }
        let pk = PublicKey {
            point: point.compress(),
        };
        Ok((pk, scalar))
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
        b.copy_from_slice(bytes);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_pk_scalar() {
        let secret_key =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap();
        let public_key =
            hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
                .unwrap();
        let secret_scalar =
            hex::decode("307c83864f2833cb427a2ef1c00a013cfdff2768d980c0a3a520f006904de94f")
                .unwrap();
        let secret_key = SecretKey::from_slice(&secret_key);
        let (pk, scalar) = secret_key.extract_public_key_and_scalar().unwrap();
        assert_eq!(pk.as_bytes(), public_key.as_slice());
        assert_eq!(scalar.as_bytes(), secret_scalar.as_slice());
    }
}

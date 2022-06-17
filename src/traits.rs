use core::fmt;

use curve25519_dalek::edwards::CompressedEdwardsY;
use schemars::{
    gen::SchemaGenerator,
    schema::{InstanceType, Schema, SchemaObject},
    JsonSchema,
};
use serde::{de::Error, Deserialize, Deserializer, Serializer};

use crate::{PublicKey, SecretKey};
use std::{fmt::Write, num::ParseIntError};

impl AsRef<[u8]> for SecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

pub fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

pub fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}

impl fmt::Display for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", encode_hex(&self.bytes))?;
        Ok(())
    }
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

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", encode_hex(self.point.as_bytes()))?;
        Ok(())
    }
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

pub fn point_from_hex<'de, D>(deserializer: D) -> Result<CompressedEdwardsY, D::Error>
where
    D: Deserializer<'de>,
{
    let s: &str = Deserialize::deserialize(deserializer)?;
    Ok(CompressedEdwardsY::from_slice(
        decode_hex(s)
            .map_err(|_| D::Error::custom("Invalid hex string"))?
            .as_slice(),
    ))
}

pub fn sk_bytes_from_hex<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
where
    D: Deserializer<'de>,
{
    let s: &str = Deserialize::deserialize(deserializer)?;
    Ok(decode_hex(s)
        .map_err(|_| D::Error::custom("Invalid hex string"))?
        .as_slice()
        .try_into()
        .map_err(|_| D::Error::custom("Invalid hex string"))?)
}

pub fn serialize_bytes<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&encode_hex(bytes))
}

pub fn serialize_point<S>(point: &CompressedEdwardsY, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&encode_hex(point.as_bytes()))
}

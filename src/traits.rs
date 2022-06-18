use core::fmt;

use schemars::{
    gen::SchemaGenerator,
    schema::{InstanceType, Schema, SchemaObject},
    JsonSchema,
};
use serde::{
    de::{Error, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};

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

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", encode_hex(self.point.as_bytes()))?;
        Ok(())
    }
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&encode_hex(self.point.as_bytes()))
    }
}

impl Serialize for SecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&encode_hex(self.as_bytes()))
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PublicKeyVisitor;

        impl<'de> Visitor<'de> for PublicKeyVisitor {
            type Value = PublicKey;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("PublicKey bytes")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                Ok(PublicKey::from_bytes(
                    decode_hex(v)
                        .map_err(|_| E::custom("Error decoding PublicKey bytes"))?
                        .as_slice(),
                ))
            }
        }

        deserializer.deserialize_str(PublicKeyVisitor)
    }
}

impl<'de> Deserialize<'de> for SecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SecretKeyVisitor;

        impl<'de> Visitor<'de> for SecretKeyVisitor {
            type Value = SecretKey;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("SecretKey bytes")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                Ok(SecretKey::from_slice(
                    decode_hex(v)
                        .map_err(|_| E::custom("Error decoding Secretkey bytes"))?
                        .as_slice(),
                ))
            }
        }

        deserializer.deserialize_str(SecretKeyVisitor)
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

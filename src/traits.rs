use core::fmt;

use schemars::{
    gen::SchemaGenerator,
    schema::{InstanceType, Schema, SchemaObject},
    JsonSchema,
};
use serde::{
    de::{Error, IgnoredAny, MapAccess, SeqAccess, Visitor},
    ser::SerializeStruct,
    Deserialize, Deserializer, Serialize, Serializer,
};

use crate::{Proof, PublicKey, SecretKey};
use std::{fmt::Write, marker::PhantomData, num::ParseIntError};

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

impl Serialize for Proof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("Proof", 3)?;
        state.serialize_field("signer", &self.signer)?;
        state.serialize_field("message", &encode_hex(&self.message_bytes))?;
        state.serialize_field("proof", &encode_hex(&self.proof_bytes))?;
        state.end()
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

impl<'de> Deserialize<'de> for Proof {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        enum Field {
            Signer,
            Message,
            Proof,
            Ignore,
        }

        struct FieldVisitor;
        
        impl<'de> Visitor<'de> for FieldVisitor {
            type Value = Field;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("field identifier")
            }

            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
            where
                E: Error,
            {
                match v {
                    0u64 => Ok(Field::Signer),
                    1u64 => Ok(Field::Message),
                    2u64 => Ok(Field::Proof),
                    _ => Ok(Field::Ignore),
                }
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                match v {
                    "signer" => Ok(Field::Signer),
                    "message" => Ok(Field::Message),
                    "proof" => Ok(Field::Proof),
                    _ => Ok(Field::Ignore),
                }
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: Error,
            {
                match v {
                    b"signer" => Ok(Field::Signer),
                    b"message" => Ok(Field::Message),
                    b"proof" => Ok(Field::Proof),
                    _ => Ok(Field::Ignore),
                }
            }
        }

        impl<'de> Deserialize<'de> for Field {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct ProofVisitor<'de> {
            marker: PhantomData<Proof>,
            lifetime: PhantomData<&'de ()>,
        }

        impl<'de> Visitor<'de> for ProofVisitor<'de> {
            type Value = Proof;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct Proof")
            }
            #[inline]
            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let signer = seq
                    .next_element::<PublicKey>()?
                    .ok_or_else(|| A::Error::invalid_length(0, &"struct Proof with 3 elements"))?;
                let message = seq
                    .next_element::<&str>()?
                    .ok_or_else(|| A::Error::invalid_length(1, &"struct Proof with 3 elements"))?;
                let proof = seq
                    .next_element::<&str>()?
                    .ok_or_else(|| A::Error::invalid_length(2, &"struct Proof with 3 elements"))?;
                Ok(Proof {
                    signer: signer,
                    message_bytes: decode_hex(message)
                        .map_err(|_| A::Error::custom("Error decoding message"))?,
                    proof_bytes: decode_hex(proof)
                        .map_err(|_| A::Error::custom("Error decoding proof"))?,
                })
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut signer = None;
                let mut message = None;
                let mut proof = None;
                while let Some(key) = map.next_key::<Field>()? {
                    match key {
                        Field::Signer => {
                            if signer.is_some() {
                                return Err(A::Error::duplicate_field("signer"));
                            }
                            signer = Some(map.next_value::<PublicKey>()?);
                        }
                        Field::Message => {
                            if message.is_some() {
                                return Err(A::Error::duplicate_field("message"));
                            }
                            message = Some(map.next_value::<&str>()?);
                        }
                        Field::Proof => {
                            if proof.is_some() {
                                return Err(A::Error::duplicate_field("proof"));
                            }
                            proof = Some(map.next_value::<&str>()?);
                        }
                        _ => {
                            let _ = match map.next_value::<IgnoredAny>() {
                                Ok(val) => val,
                                Err(e) => return Err(e),
                            };
                        }
                    }
                }
                let signer = signer.ok_or_else(|| A::Error::missing_field("signer"))?;
                let message = message.ok_or_else(|| A::Error::missing_field("message"))?;
                let proof = proof.ok_or_else(|| A::Error::missing_field("proof"))?;
                Ok(Proof {
                    signer: signer,
                    message_bytes: decode_hex(message)
                        .map_err(|_| A::Error::custom("Error decoding message"))?,
                    proof_bytes: decode_hex(proof)
                        .map_err(|_| A::Error::custom("Error decoding proof"))?,
                })
            }
        }

        const FIELDS: &'static [&'static str] = &["signer", "message", "proof"];
        deserializer.deserialize_struct(
            "Proof",
            FIELDS,
            ProofVisitor {
                marker: PhantomData::<Proof>,
                lifetime: PhantomData,
            },
        )
    }
}

impl JsonSchema for SecretKey {
    fn schema_name() -> String {
        "SecretKey".to_owned()
    }
    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        let mut schema_object = SchemaObject {
            instance_type: Some(InstanceType::String.into()),
            ..Default::default()
        };
        let string_validation = schema_object.string();
        string_validation.min_length = Some(64u32);
        string_validation.max_length = Some(64u32);
        Schema::Object(schema_object)
    }
}

impl JsonSchema for PublicKey {
    fn schema_name() -> String {
        "PublicKey".to_owned()
    }
    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        let mut schema_object = SchemaObject {
            instance_type: Some(InstanceType::String.into()),
            ..Default::default()
        };
        let string_validation = schema_object.string();
        string_validation.min_length = Some(64u32);
        string_validation.max_length = Some(64u32);
        Schema::Object(schema_object)
    }
}

impl JsonSchema for Proof {
    fn schema_name() -> String {
        "Proof".to_owned()
    }

    fn json_schema(gen: &mut SchemaGenerator) -> Schema {
        let mut schema_object = SchemaObject {
            instance_type: Some(InstanceType::Object.into()),
            ..Default::default()
        };
        let object_validation = schema_object.object();
        {
            // signer
            object_validation
                .properties
                .insert("signer".to_owned(), gen.subschema_for::<PublicKey>());
            object_validation.required.insert("signer".to_owned());
        }
        {
            // message
            object_validation
                .properties
                .insert("message".to_owned(), gen.subschema_for::<String>());
            object_validation.required.insert("message".to_owned());
        }

        {
            // proof
            object_validation
                .properties
                .insert("proof".to_owned(), gen.subschema_for::<String>());
            object_validation.required.insert("proof".to_owned());
        }
        Schema::Object(schema_object)
    }
}

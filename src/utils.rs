use curve25519_dalek::{
    constants::{BASEPOINT_ORDER, ED25519_BASEPOINT_POINT},
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
};
use sha2::{Digest, Sha512};

use crate::{
    errors::VRFError,
    keys::{PublicKey, SecretKey},
    proof::Proof,
};

pub fn sha512(input: impl AsRef<[u8]>) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(input);
    hasher.finalize().into()
}

/// Computes a hash of the given message on the ed25519 curve, using elligator2 encoding.
pub fn hash_to_curve_ell2(pk: &PublicKey, alpha_string: &[u8]) -> EdwardsPoint {
    let v = [&[4u8, 1u8], pk.as_bytes(), alpha_string].concat();
    let mut hash: [u8; 32] = sha512(&v)[..32].try_into().unwrap();
    hash[31] &= 0x7F;

    EdwardsPoint::bytes_to_curve(&hash)
}

/// ECVRF nonce generation according to Section 5.1.6 of [RFC8032](https://tools.ietf.org/html/rfc8032).
pub fn nonce_gen(sk: &SecretKey, point: EdwardsPoint) -> [u8; 64] {
    let key_hash: [u8; 32] = sha512(&sk)[32..].try_into().unwrap();
    let v = [&key_hash[..], point.compress().as_bytes()].concat();

    sha512(&v)
}

/// `ECVRF_challenge_generation` -- Hashes several points on the curve
pub fn hash_points(points: &[&CompressedEdwardsY]) -> [u8; 32] {
    let mut v = vec![4u8, 2u8];
    points
        .iter()
        .for_each(|p| v.extend_from_slice(p.as_bytes()));
    let mut hash: [u8; 32] = [0u8; 32];
    hash[..16].copy_from_slice(&sha512(&v)[..16]);
    hash
}

pub fn decode_proof(proof_bytes: &[u8]) -> Result<([u8; 32], [u8; 16], [u8; 32]), VRFError> {
    let gamma = &proof_bytes[..32];
    let c = &proof_bytes[32..48];
    let s = &proof_bytes[48..80];
    Ok((
        gamma
            .try_into()
            .map_err(|_| VRFError::DecodeProofError {})?,
        c.try_into().map_err(|_| VRFError::DecodeProofError {})?,
        s.try_into().map_err(|_| VRFError::DecodeProofError {})?,
    ))
}

pub fn proof_to_hash(proof_bytes: &[u8]) -> Result<[u8; 64], VRFError> {
    let (gamma, _, _) = decode_proof(proof_bytes)?;
    let gamma = CompressedEdwardsY::from_slice(&gamma);
    let gamma = gamma
        .decompress()
        .ok_or(VRFError::InvalidProof {})?
        .mul_by_cofactor()
        .compress();
    let v = [&[4u8, 3u8], &gamma.as_bytes()[..], &[0u8]].concat();

    Ok(sha512(&v))
}

pub fn verify_proof(proof: &Proof) -> Result<[u8; 64], VRFError> {
    let pk_point = proof
        .signer
        .as_point()
        .decompress()
        .ok_or(VRFError::InvalidPublicKey {})?;

    let (gamma, c, s) = decode_proof(&proof.proof_bytes)?;
    let point = hash_to_curve_ell2(&proof.signer, &proof.message_bytes);
    let c = Scalar::from_bits([&c[..], &[0u8; 16]].concat().try_into().unwrap());
    let s = Scalar::from_bits(s);
    let gamma = CompressedEdwardsY::from_slice(&gamma);

    let c_y = pk_point * c;
    let s_b = s * ED25519_BASEPOINT_POINT;
    let u = s_b - c_y;

    let s_h = s * point;
    let c_g = c * gamma.decompress().ok_or(VRFError::InvalidProof {})?;
    let v = s_h - c_g;

    let c_prime = hash_points(&[
        proof.signer.as_point(),
        &point.compress(),
        &gamma,
        &u.compress(),
        &v.compress(),
    ]);

    if c_prime == c.to_bytes() {
        Ok(proof_to_hash(&proof.proof_bytes)?)
    } else {
        Err(VRFError::InvalidProof {})
    }
}

pub fn prove(secret_key: &SecretKey, alpha_string: &[u8]) -> Result<Proof, VRFError> {
    // Extract the public key and VRF scalar from the secret key
    let (pk, scalar) = secret_key.extract_public_key_and_scalar()?;

    // Compute the point on the curve corresponding to the hash of the input
    let point = hash_to_curve_ell2(&pk, alpha_string);

    // Compute the nonce and the challenge
    let gamma = (scalar * point).compress();
    let k = Scalar::from_bytes_mod_order_wide(&nonce_gen(secret_key, point));
    let k_b = (k * ED25519_BASEPOINT_POINT).compress();
    let k_h = (k * point).compress();
    //&[pk, point.compress(), gamma, k_b, k_h]
    let c = hash_points(&[pk.as_point(), &point.compress(), &gamma, &k_b, &k_h]);
    let c_scalar = Scalar::from_bytes_mod_order(c);

    // Compute the proof
    let s = k + (c_scalar * scalar);
    // Calculate s % BASEPOINT_ORDER
    let s_over_base = s * BASEPOINT_ORDER.invert();
    let s = s - (s_over_base * BASEPOINT_ORDER);

    let pi_string = [&gamma.as_bytes()[..], &c[..16], &s.to_bytes()[..]].concat();

    Ok(Proof {
        signer: pk,
        message_bytes: alpha_string.to_vec(),
        proof_bytes: pi_string,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_hash_to_curve() {
        let pk = hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
            .unwrap();
        let h = hex::decode("1c5672d919cc0a800970cd7e05cb36ed27ed354c33519948e5a9eaf89aee12b7")
            .unwrap();

        let pk = PublicKey::from_bytes(&pk);
        let alpha_string = b"";
        let point = hash_to_curve_ell2(&pk, alpha_string);
        assert_eq!(point.compress().as_bytes(), h.as_slice());
    }

    #[test]
    fn test_verify() {
        let public_key =
            hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
                .unwrap();
        let pi_string =
            hex::decode("b6b4699f87d56126c9117a7da55bd0085246f4c56dbc95d20172612e9d38e8d7c3a8dc589866501fe1724fc5ef3b32412d2983949049428b4ebbc86bdfbbbc4e0c51cb22e78ed55fd1ad4743014f6701")
            .unwrap();
        let alpha_string = b"";
        let result = verify_proof(&Proof {
            signer: PublicKey::from_bytes(&public_key),
            message_bytes: Vec::from(*alpha_string),
            proof_bytes: pi_string,
        });
        assert!(result.is_ok(), "Result is ok");
        let beta_string = result.unwrap();
        assert_eq!(beta_string, hex::decode("e84a28279ee1af17a63917d185ef7946a7a51b844a2b99f3f835d7862f4cf26629fd5f53d51ae4100e5644db915738cf3f76d06757c8f7538057f5834111c6e7").unwrap().as_slice());
    }

    #[test]
    fn test_proof() {
        let secret_key =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap();

        let alpha_string = b"";
        let proof = prove(&SecretKey::from_slice(&secret_key), alpha_string).unwrap();
        assert_eq!(proof.proof_bytes, hex::decode("b6b4699f87d56126c9117a7da55bd0085246f4c56dbc95d20172612e9d38e8d7c3a8dc589866501fe1724fc5ef3b32412d2983949049428b4ebbc86bdfbbbc4e0c51cb22e78ed55fd1ad4743014f6701").unwrap().as_slice());
        let beta_string = proof_to_hash(&proof.proof_bytes).unwrap();
        assert_eq!(beta_string, hex::decode("e84a28279ee1af17a63917d185ef7946a7a51b844a2b99f3f835d7862f4cf26629fd5f53d51ae4100e5644db915738cf3f76d06757c8f7538057f5834111c6e7").unwrap().as_slice());
    }
}

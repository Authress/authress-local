use std::ops::Add;

use base64::{engine, Engine};
use chrono::Duration;
use ed25519::pkcs8::EncodePrivateKey;
use serde::{Serialize, Deserialize};
use jsonwebtoken::{encode, Header, Algorithm, EncodingKey};
use ed25519_dalek::SigningKey;

use rand_core::OsRng;

#[derive(Debug, Clone)]
pub struct SignatureKey {
    pub key_pair: SigningKey
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JWK {
    pub kty: String,
    pub alg: String,
    pub crv: String,
    pub x: String,
    pub kid: String
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JwkList {
    pub keys: Vec<JWK>
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OpenIdConfiguration {
    pub jwk_uri: String
}

#[derive(Debug, Serialize, Deserialize)]
struct JwtPayload {
    aud: String,         // Optional. Audience
    exp: usize,          // Required (validate_exp defaults to true in validation). Expiration time (as UTC timestamp)
    iat: usize,          // Optional. Issued at (as UTC timestamp)
    iss: String,         // Optional. Issuer
    sub: String,         // Optional. Subject (whom token refers to)
}

impl Default for SignatureKey {
    fn default() -> SignatureKey {
        let mut secure_random_number = OsRng;
        let signing_key = SigningKey::generate(&mut secure_random_number);

        return SignatureKey {
            key_pair: signing_key
        }
    }
}

impl SignatureKey {
    pub fn create_token(&self, host: &str) -> String {
        let payload = JwtPayload {
            aud: "localhost".to_owned(),
            exp: usize::try_from(chrono::offset::Local::now().add(Duration::days(1)).timestamp()).unwrap(),
            iat: usize::try_from(chrono::offset::Local::now().timestamp()).unwrap(),
            iss: format!("https//{host}"),
            sub: "me".to_owned(),
        };
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some("authress-local".to_owned());
        let signing_key = EncodingKey::from_ed_pem(&self.key_pair.to_pkcs8_pem(ed25519::pkcs8::spki::der::pem::LineEnding::LF).unwrap().as_bytes()).unwrap();
        let token = encode(&header, &payload, &signing_key).unwrap();
        return token;
    }

    pub fn get_openid_configuration(&self, host: &str) -> OpenIdConfiguration {
        return OpenIdConfiguration {
            jwk_uri: format!("https//{host}/.well-known/openid-configuration/jwks")
        };
    }

    pub fn get_jwks(&self) -> JwkList {
        let jwk = JWK {
            kty: "OKP".to_owned(),
            crv: "Ed25519".to_owned(),
            alg: "EdDSA".to_owned(),
            kid: "authress-local".to_owned(),
            x: engine::general_purpose::URL_SAFE_NO_PAD.encode(self.key_pair.verifying_key().to_bytes())
        };
        return JwkList {
            keys: vec![jwk]
        };
    }
}
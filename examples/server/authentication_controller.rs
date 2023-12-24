use serde::{Serialize, Deserialize};

use crate::{*, authentication::SignatureKey};

#[derive(Debug, Serialize, Deserialize)]
pub struct JwkList {
    pub keys: Vec<authentication::JWK>
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

#[derive(Debug, Default, Clone, Copy)]
pub struct AuthenticationController {}

impl AuthenticationController {
    pub fn start_authentication(&self, host: &str, signature_key: SignatureKey) -> String {
        return "".to_owned();
    }

    pub fn get_token(&self, host: &str, signature_key: SignatureKey) -> String {
        let token = signature_key.create_token(host);

        // TODO This should be an Object and we should be setting things in the response URL
        return token;
    }

    pub fn get_openid_configuration(&self, host: &str) -> OpenIdConfiguration {
        return OpenIdConfiguration {
            jwk_uri: format!("https//{host}/.well-known/openid-configuration/jwks")
        };
    }

    pub fn get_jwks(&self, signature_key: SignatureKey) -> JwkList {
        return JwkList {
            keys: vec![signature_key.get_jwk()]
        };
    }
}
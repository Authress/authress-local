use authress_local::authentication::AuthenticationRequest;
use serde::{Serialize, Deserialize};
use url::Url;
use crate::{*, authentication::SignatureKey};

#[derive(Debug, Serialize, Deserialize)]
pub struct JwkList {
    pub keys: Vec<authentication::JWK>
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OpenIdConfiguration {
    pub jwk_uri: String
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(frunk::LabelledGeneric))]
pub struct StartAuthenticationResponse {
    #[serde(rename = "authenticationUrl")]
    pub authentication_url: String,

    #[serde(rename = "authenticationRequestId")]
    pub authentication_request_id: String
}

#[derive(Debug, Default, Clone, Copy)]
pub struct AuthenticationController {}

impl AuthenticationController {
    pub fn start_authentication(&self, host: &str, authentication_request: AuthenticationRequest, signature_key: SignatureKey) -> StartAuthenticationResponse {
        let request_id = "RequestId";
        
        let access_token = signature_key.create_token(host);
        let id_token = signature_key.create_id_token(host);

        let url = Url::parse_with_params(&authentication_request.redirect_url,
            &[("access_token", &access_token), ("id_token", &id_token), ("nonce", &request_id.to_string())]
        ).unwrap();

        return StartAuthenticationResponse {
            authentication_request_id: request_id.to_string(),
            authentication_url: url.to_string()
        }
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
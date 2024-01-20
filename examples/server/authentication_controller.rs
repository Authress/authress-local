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
    pub jwks_uri: String,
    pub token_endpoint: String,
    pub authorization_endpoint: String
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(frunk::LabelledGeneric))]
pub struct StartAuthenticationResponse {
    #[serde(rename = "authenticationUrl", skip_serializing_if="Option::is_none")]
    pub authentication_url: Option<String>,

    #[serde(rename = "authenticationRequestId", skip_serializing_if="Option::is_none")]
    pub authentication_request_id: Option<String>,

    #[serde(rename = "accessToken", skip_serializing_if="Option::is_none")]
    pub access_token: Option<String>
}

#[derive(Debug, Default, Clone, Copy)]
pub struct AuthenticationController {}

impl AuthenticationController {
    pub fn start_authentication(&self, host: &str, authentication_request: AuthenticationRequest, signature_key: SignatureKey) -> StartAuthenticationResponse {
        let request_id = "RequestId";
        
        let access_token = signature_key.create_token(host);
        let id_token = signature_key.create_id_token(host);

        if let Some(redirect_url) = authentication_request.redirect_url {
            let parsed_url = Url::parse_with_params(&redirect_url,
                &[("access_token", &access_token), ("id_token", &id_token), ("nonce", &request_id.to_string())]
            );
            if let Ok(url) = parsed_url {
                return StartAuthenticationResponse {
                    authentication_request_id: Some(request_id.to_string()),
                    authentication_url: Some(url.to_string()),
                    access_token: Some(access_token)
                }
            }
        }

        return StartAuthenticationResponse {
            authentication_request_id: None,
            authentication_url: None,
            access_token: Some(access_token)
        }
    }

    pub fn get_token(&self, host: &str, signature_key: SignatureKey) -> String {
        let token = signature_key.create_token(host);

        // TODO This should be an Object and we should be setting things in the response URL
        return token;
    }

    pub fn get_openid_configuration(&self, host: &str) -> OpenIdConfiguration {
        return OpenIdConfiguration {
            jwks_uri: format!("http://{host}/.well-known/openid-configuration/jwks"),
            authorization_endpoint: format!("http://{host}"),
            token_endpoint: format!("http://{host}/api/authentication/oauth/tokens"),
        };
    }

    pub fn get_jwks(&self, signature_key: SignatureKey) -> JwkList {
        return JwkList {
            keys: vec![signature_key.get_jwk()]
        };
    }
}
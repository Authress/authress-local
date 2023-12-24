// These are the traits or really the implementation interface for the declared functions It isn't used directly

#![allow(missing_docs, trivial_casts, unused_variables, unused_mut, unused_imports, unused_extern_crates, non_camel_case_types)]
#![allow(unused_imports, unused_attributes)]
#![allow(clippy::derive_partial_eq_without_eq, clippy::disallowed_names)]

use async_trait::async_trait;
use authress::models::*;
use futures::Stream;
use log::*;
use std::error::Error;
use std::task::{Poll, Context};
use serde::{Serialize, Deserialize};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum LoginResponse {
    /// Success.
    Success
    (String)
    ,
    /// Bad Request. There are one or more issues with the request that prevent the service from returning a valid token
    BadRequest
    ,
    /// Unauthorized. The credentials and temporary security token provided in the request is invalid
    Unauthorized
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum RequestTokenResponse {
    /// Success. The credentials provided are valid and token has been created.
    Success
    (String)
    ,
    /// Bad Request. There are one or more issues with the request that prevent the service from returning a valid token
    BadRequest
    ,
    /// Unauthorized. The credentials and temporary security token provided in the request is invalid
    Unauthorized
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum OpenIdConfigurationResponse {
    Success(String)
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum JwksResponse {
    Success(String)
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum AuthenticationResponse {
    Success(String)
}

#[derive(Default, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuthenticationRequest {
    // /// The client identifier to constrain the token to.
    // #[serde(rename = "client_id")]
    // pub client_id: String,
    // /// The secret associated with the client that authorizes the generation of token it's behalf. (Either the `client_secret` or the `code_verifier` is required)
    // #[serde(rename = "client_secret", default, with = "::serde_with::rust::double_option", skip_serializing_if = "Option::is_none")]
    // pub client_secret: Option<Option<String>>,
    // /// The code verifier is the the value used in the generation of the OAuth authorization request `code_challenge` property. (Either the `client_secret` or the `code_verifier` is required)
    // #[serde(rename = "code_verifier", skip_serializing_if = "Option::is_none")]
    // pub code_verifier: Option<String>,
    // /// A suggestion to the token generation which type of credentials are being provided.
    // #[serde(rename = "grant_type", skip_serializing_if = "Option::is_none")]
    // pub grant_type: Option<GrantType>,
    // /// When using the user password grant_type, specify the username. Authress recommends this should always be an email address.
    // #[serde(rename = "username", default, with = "::serde_with::rust::double_option", skip_serializing_if = "Option::is_none")]
    // pub username: Option<Option<String>>,
    // /// When using the user password grant_type, specify the user's password.
    // #[serde(rename = "password", default, with = "::serde_with::rust::double_option", skip_serializing_if = "Option::is_none")]
    // pub password: Option<Option<String>>,
    // /// Enables additional configuration of the grant_type. In the case of user password grant_type, set this to **signup**, to enable the creation of users. Set this to **update**, force update the password associated with the user.
    // #[serde(rename = "type", default, with = "::serde_with::rust::double_option", skip_serializing_if = "Option::is_none")]
    // pub r#type: Option<Option<Type>>,
}

impl AuthenticationRequest {
    pub fn new(client_id: String) -> AuthenticationRequest {
        AuthenticationRequest {
            // client_id,
            // client_secret: None,
            // code_verifier: None,
            // grant_type: None,
            // username: None,
            // password: None,
            // r#type: None,
        }
    }
}
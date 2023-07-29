// This is the Router + Service Controller, which calls into the servers.rs implementation


use futures::{future, future::BoxFuture, Stream, stream, future::FutureExt, stream::TryStreamExt};
use hyper::{Request, Response, StatusCode, Body, HeaderMap};
use hyper::header::{HeaderName, HeaderValue, CONTENT_TYPE};
use log::*;
#[allow(unused_imports)]
use std::convert::{TryFrom, TryInto};
use std::error::Error;
use std::future::Future;
use std::marker::PhantomData;
use std::task::{Context, Poll};
use swagger::{BodyExt, Has, RequestParser, XSpanIdString};
pub use swagger::auth::Authorization;
use swagger::auth::Scopes;
use url::form_urlencoded;

#[allow(unused_imports)]
use crate::header;

pub use crate::context;

type ServiceFuture = BoxFuture<'static, Result<Response<Body>, crate::ServiceError>>;

use authress::models::*;
use crate::{Api,
     CreateClaimResponse,
     CreateInviteResponse,
     CreateRecordResponse,
     CreateRequestResponse,
     DeleteInviteResponse,
     DeleteRecordResponse,
     DeleteRequestResponse,
     GetRecordResponse,
     GetRecordsResponse,
     GetRequestResponse,
     GetRequestsResponse,
     RespondToAccessRequestResponse,
     RespondToInviteResponse,
     UpdateRecordResponse,
     DelegateAuthenticationResponse,
     GetAccountResponse,
     GetAccountIdentitiesResponse,
     GetAccountsResponse,
     DelegateUserLoginResponse,
     CreateConnectionResponse,
     DeleteConnectionResponse,
     GetConnectionResponse,
     GetConnectionCredentialsResponse,
     GetConnectionsResponse,
     UpdateConnectionResponse,
     CreateExtensionResponse,
     DeleteExtensionResponse,
     GetExtensionResponse,
     GetExtensionsResponse,
     LoginResponse,
     RequestTokenResponse,
     UpdateExtensionResponse,
     CreateGroupResponse,
     DeleteGroupResponse,
     GetGroupResponse,
     GetGroupsResponse,
     UpdateGroupResponse,
     GetPermissionedResourceResponse,
     GetPermissionedResourcesResponse,
     GetResourceUsersResponse,
     UpdatePermissionedResourceResponse,
     CreateRoleResponse,
     DeleteRoleResponse,
     GetRoleResponse,
     GetRolesResponse,
     UpdateRoleResponse,
     CreateClientResponse,
     DeleteAccessKeyResponse,
     DeleteClientResponse,
     GetClientResponse,
     GetClientsResponse,
     RequestAccessKeyResponse,
     UpdateClientResponse,
     CreateTenantResponse,
     DeleteTenantResponse,
     GetTenantResponse,
     GetTenantsResponse,
     UpdateTenantResponse,
     AuthorizeUserResponse,
     GetUserPermissionsForResourceResponse,
     GetUserResourcesResponse,
     GetUserRolesForResourceResponse,
     DeleteUserResponse,
     GetUserResponse,
     GetUsersResponse, ApiError
};

pub const IMPLEMENTATION_NOT_YET_AVAILABLE_ERROR_STRING: &str = "
************************************************************************************************************
************************************************************************************************************

Implementation not yet available. Please file a ticket at https://github.com/Authress/authress-local/issues.

************************************************************************************************************
************************************************************************************************************\n";

mod paths {
    use lazy_static::lazy_static;

    lazy_static! {
        pub static ref GLOBAL_REGEX_SET: regex::RegexSet = regex::RegexSet::new(vec![
            r"^/$",
            r"^/api/authentication/oauth/tokens$",
            r"^/v1/accounts$",
            r"^/v1/accounts/(?P<accountId>[^/?#]*)$",
            r"^/v1/applications/(?P<applicationId>[^/?#]*)/users/(?P<userId>[^/?#]*)/delegation$",
            r"^/v1/claims$",
            r"^/v1/clients$",
            r"^/v1/clients/(?P<clientId>[^/?#]*)$",
            r"^/v1/clients/(?P<clientId>[^/?#]*)/access-keys$",
            r"^/v1/clients/(?P<clientId>[^/?#]*)/access-keys/(?P<keyId>[^/?#]*)$",
            r"^/v1/connections$",
            r"^/v1/connections/(?P<connectionId>[^/?#]*)$",
            r"^/v1/connections/(?P<connectionId>[^/?#]*)/users/(?P<userId>[^/?#]*)/credentials$",
            r"^/v1/extensions$",
            r"^/v1/extensions/(?P<extensionId>[^/?#]*)$",
            r"^/v1/groups$",
            r"^/v1/groups/(?P<groupId>[^/?#]*)$",
            r"^/v1/identities$",
            r"^/v1/invites$",
            r"^/v1/invites/(?P<inviteId>[^/?#]*)$",
            r"^/v1/records$",
            r"^/v1/records/(?P<recordId>[^/?#]*)$",
            r"^/v1/requests$",
            r"^/v1/requests/(?P<requestId>[^/?#]*)$",
            r"^/v1/resources$",
            r"^/v1/resources/(?P<resourceUri>[^/?#]*)$",
            r"^/v1/resources/(?P<resourceUri>[^/?#]*)/users$",
            r"^/v1/roles$",
            r"^/v1/roles/(?P<roleId>[^/?#]*)$",
            r"^/v1/tenants$",
            r"^/v1/tenants/(?P<tenantId>[^/?#]*)$",
            r"^/v1/users$",
            r"^/v1/users/(?P<userId>[^/?#]*)$",
            r"^/v1/users/(?P<userId>[^/?#]*)/resources$",
            r"^/v1/users/(?P<userId>[^/?#]*)/resources/(?P<resourceUri>[^/?#]*)/permissions$",
            r"^/v1/users/(?P<userId>[^/?#]*)/resources/(?P<resourceUri>[^/?#]*)/permissions/(?P<permission>[^/?#]*)$",
            r"^/v1/users/(?P<userId>[^/?#]*)/resources/(?P<resourceUri>[^/?#]*)/roles$"
        ])
        .expect("Unable to create global regex set");
    }
    pub(crate) static ID_: usize = 0;
    pub(crate) static ID_API_AUTHENTICATION_OAUTH_TOKENS: usize = 1;
    pub(crate) static ID_V1_ACCOUNTS: usize = 2;
    pub(crate) static ID_V1_ACCOUNTS_ACCOUNTID: usize = 3;
    lazy_static! {
        pub static ref REGEX_V1_ACCOUNTS_ACCOUNTID: regex::Regex =
            #[allow(clippy::invalid_regex)]
            regex::Regex::new(r"^/v1/accounts/(?P<accountId>[^/?#]*)$")
                .expect("Unable to create regex for V1_ACCOUNTS_ACCOUNTID");
    }
    pub(crate) static ID_V1_APPLICATIONS_APPLICATIONID_USERS_USERID_DELEGATION: usize = 4;
    lazy_static! {
        pub static ref REGEX_V1_APPLICATIONS_APPLICATIONID_USERS_USERID_DELEGATION: regex::Regex =
            #[allow(clippy::invalid_regex)]
            regex::Regex::new(r"^/v1/applications/(?P<applicationId>[^/?#]*)/users/(?P<userId>[^/?#]*)/delegation$")
                .expect("Unable to create regex for V1_APPLICATIONS_APPLICATIONID_USERS_USERID_DELEGATION");
    }
    pub(crate) static ID_V1_CLAIMS: usize = 5;
    pub(crate) static ID_V1_CLIENTS: usize = 6;
    pub(crate) static ID_V1_CLIENTS_CLIENTID: usize = 7;
    lazy_static! {
        pub static ref REGEX_V1_CLIENTS_CLIENTID: regex::Regex =
            #[allow(clippy::invalid_regex)]
            regex::Regex::new(r"^/v1/clients/(?P<clientId>[^/?#]*)$")
                .expect("Unable to create regex for V1_CLIENTS_CLIENTID");
    }
    pub(crate) static ID_V1_CLIENTS_CLIENTID_ACCESS_KEYS: usize = 8;
    lazy_static! {
        pub static ref REGEX_V1_CLIENTS_CLIENTID_ACCESS_KEYS: regex::Regex =
            #[allow(clippy::invalid_regex)]
            regex::Regex::new(r"^/v1/clients/(?P<clientId>[^/?#]*)/access-keys$")
                .expect("Unable to create regex for V1_CLIENTS_CLIENTID_ACCESS_KEYS");
    }
    pub(crate) static ID_V1_CLIENTS_CLIENTID_ACCESS_KEYS_KEYID: usize = 9;
    lazy_static! {
        pub static ref REGEX_V1_CLIENTS_CLIENTID_ACCESS_KEYS_KEYID: regex::Regex =
            #[allow(clippy::invalid_regex)]
            regex::Regex::new(r"^/v1/clients/(?P<clientId>[^/?#]*)/access-keys/(?P<keyId>[^/?#]*)$")
                .expect("Unable to create regex for V1_CLIENTS_CLIENTID_ACCESS_KEYS_KEYID");
    }
    pub(crate) static ID_V1_CONNECTIONS: usize = 10;
    pub(crate) static ID_V1_CONNECTIONS_CONNECTIONID: usize = 11;
    lazy_static! {
        pub static ref REGEX_V1_CONNECTIONS_CONNECTIONID: regex::Regex =
            #[allow(clippy::invalid_regex)]
            regex::Regex::new(r"^/v1/connections/(?P<connectionId>[^/?#]*)$")
                .expect("Unable to create regex for V1_CONNECTIONS_CONNECTIONID");
    }
    pub(crate) static ID_V1_CONNECTIONS_CONNECTIONID_USERS_USERID_CREDENTIALS: usize = 12;
    lazy_static! {
        pub static ref REGEX_V1_CONNECTIONS_CONNECTIONID_USERS_USERID_CREDENTIALS: regex::Regex =
            #[allow(clippy::invalid_regex)]
            regex::Regex::new(r"^/v1/connections/(?P<connectionId>[^/?#]*)/users/(?P<userId>[^/?#]*)/credentials$")
                .expect("Unable to create regex for V1_CONNECTIONS_CONNECTIONID_USERS_USERID_CREDENTIALS");
    }
    pub(crate) static ID_V1_EXTENSIONS: usize = 13;
    pub(crate) static ID_V1_EXTENSIONS_EXTENSIONID: usize = 14;
    lazy_static! {
        pub static ref REGEX_V1_EXTENSIONS_EXTENSIONID: regex::Regex =
            #[allow(clippy::invalid_regex)]
            regex::Regex::new(r"^/v1/extensions/(?P<extensionId>[^/?#]*)$")
                .expect("Unable to create regex for V1_EXTENSIONS_EXTENSIONID");
    }
    pub(crate) static ID_V1_GROUPS: usize = 15;
    pub(crate) static ID_V1_GROUPS_GROUPID: usize = 16;
    lazy_static! {
        pub static ref REGEX_V1_GROUPS_GROUPID: regex::Regex =
            #[allow(clippy::invalid_regex)]
            regex::Regex::new(r"^/v1/groups/(?P<groupId>[^/?#]*)$")
                .expect("Unable to create regex for V1_GROUPS_GROUPID");
    }
    pub(crate) static ID_V1_IDENTITIES: usize = 17;
    pub(crate) static ID_V1_INVITES: usize = 18;
    pub(crate) static ID_V1_INVITES_INVITEID: usize = 19;
    lazy_static! {
        pub static ref REGEX_V1_INVITES_INVITEID: regex::Regex =
            #[allow(clippy::invalid_regex)]
            regex::Regex::new(r"^/v1/invites/(?P<inviteId>[^/?#]*)$")
                .expect("Unable to create regex for V1_INVITES_INVITEID");
    }
    pub(crate) static ID_V1_RECORDS: usize = 20;
    pub(crate) static ID_V1_RECORDS_RECORDID: usize = 21;
    lazy_static! {
        pub static ref REGEX_V1_RECORDS_RECORDID: regex::Regex =
            #[allow(clippy::invalid_regex)]
            regex::Regex::new(r"^/v1/records/(?P<recordId>[^/?#]*)$")
                .expect("Unable to create regex for V1_RECORDS_RECORDID");
    }
    pub(crate) static ID_V1_REQUESTS: usize = 22;
    pub(crate) static ID_V1_REQUESTS_REQUESTID: usize = 23;
    lazy_static! {
        pub static ref REGEX_V1_REQUESTS_REQUESTID: regex::Regex =
            #[allow(clippy::invalid_regex)]
            regex::Regex::new(r"^/v1/requests/(?P<requestId>[^/?#]*)$")
                .expect("Unable to create regex for V1_REQUESTS_REQUESTID");
    }
    pub(crate) static ID_V1_RESOURCES: usize = 24;
    pub(crate) static ID_V1_RESOURCES_RESOURCEURI: usize = 25;
    lazy_static! {
        pub static ref REGEX_V1_RESOURCES_RESOURCEURI: regex::Regex =
            #[allow(clippy::invalid_regex)]
            regex::Regex::new(r"^/v1/resources/(?P<resourceUri>[^/?#]*)$")
                .expect("Unable to create regex for V1_RESOURCES_RESOURCEURI");
    }
    pub(crate) static ID_V1_RESOURCES_RESOURCEURI_USERS: usize = 26;
    lazy_static! {
        pub static ref REGEX_V1_RESOURCES_RESOURCEURI_USERS: regex::Regex =
            #[allow(clippy::invalid_regex)]
            regex::Regex::new(r"^/v1/resources/(?P<resourceUri>[^/?#]*)/users$")
                .expect("Unable to create regex for V1_RESOURCES_RESOURCEURI_USERS");
    }
    pub(crate) static ID_V1_ROLES: usize = 27;
    pub(crate) static ID_V1_ROLES_ROLEID: usize = 28;
    lazy_static! {
        pub static ref REGEX_V1_ROLES_ROLEID: regex::Regex =
            #[allow(clippy::invalid_regex)]
            regex::Regex::new(r"^/v1/roles/(?P<roleId>[^/?#]*)$")
                .expect("Unable to create regex for V1_ROLES_ROLEID");
    }
    pub(crate) static ID_V1_TENANTS: usize = 29;
    pub(crate) static ID_V1_TENANTS_TENANTID: usize = 30;
    lazy_static! {
        pub static ref REGEX_V1_TENANTS_TENANTID: regex::Regex =
            #[allow(clippy::invalid_regex)]
            regex::Regex::new(r"^/v1/tenants/(?P<tenantId>[^/?#]*)$")
                .expect("Unable to create regex for V1_TENANTS_TENANTID");
    }
    pub(crate) static ID_V1_USERS: usize = 31;
    pub(crate) static ID_V1_USERS_USERID: usize = 32;
    lazy_static! {
        pub static ref REGEX_V1_USERS_USERID: regex::Regex =
            #[allow(clippy::invalid_regex)]
            regex::Regex::new(r"^/v1/users/(?P<userId>[^/?#]*)$")
                .expect("Unable to create regex for V1_USERS_USERID");
    }
    pub(crate) static ID_V1_USERS_USERID_RESOURCES: usize = 33;
    lazy_static! {
        pub static ref REGEX_V1_USERS_USERID_RESOURCES: regex::Regex =
            #[allow(clippy::invalid_regex)]
            regex::Regex::new(r"^/v1/users/(?P<userId>[^/?#]*)/resources$")
                .expect("Unable to create regex for V1_USERS_USERID_RESOURCES");
    }
    pub(crate) static ID_V1_USERS_USERID_RESOURCES_RESOURCEURI_PERMISSIONS: usize = 34;
    lazy_static! {
        pub static ref REGEX_V1_USERS_USERID_RESOURCES_RESOURCEURI_PERMISSIONS: regex::Regex =
            #[allow(clippy::invalid_regex)]
            regex::Regex::new(r"^/v1/users/(?P<userId>[^/?#]*)/resources/(?P<resourceUri>[^/?#]*)/permissions$")
                .expect("Unable to create regex for V1_USERS_USERID_RESOURCES_RESOURCEURI_PERMISSIONS");
    }
    pub(crate) static ID_V1_USERS_USERID_RESOURCES_RESOURCEURI_PERMISSIONS_PERMISSION: usize = 35;
    lazy_static! {
        pub static ref REGEX_V1_USERS_USERID_RESOURCES_RESOURCEURI_PERMISSIONS_PERMISSION: regex::Regex =
            #[allow(clippy::invalid_regex)]
            regex::Regex::new(r"^/v1/users/(?P<userId>[^/?#]*)/resources/(?P<resourceUri>[^/?#]*)/permissions/(?P<permission>[^/?#]*)$")
                .expect("Unable to create regex for V1_USERS_USERID_RESOURCES_RESOURCEURI_PERMISSIONS_PERMISSION");
    }
    pub(crate) static ID_V1_USERS_USERID_RESOURCES_RESOURCEURI_ROLES: usize = 36;
    lazy_static! {
        pub static ref REGEX_V1_USERS_USERID_RESOURCES_RESOURCEURI_ROLES: regex::Regex =
            #[allow(clippy::invalid_regex)]
            regex::Regex::new(r"^/v1/users/(?P<userId>[^/?#]*)/resources/(?P<resourceUri>[^/?#]*)/roles$")
                .expect("Unable to create regex for V1_USERS_USERID_RESOURCES_RESOURCEURI_ROLES");
    }
}

pub struct MakeService<T, C> where
    T: Api<C> + Clone + Send + 'static,
    C: Has<XSpanIdString> + Has<Option<Authorization>> + Send + Sync + 'static
{
    api_impl: T,
    marker: PhantomData<C>,
}

impl<T, C> MakeService<T, C> where
    T: Api<C> + Clone + Send + 'static,
    C: Has<XSpanIdString> + Has<Option<Authorization>> + Send + Sync + 'static
{
    pub fn new(api_impl: T) -> Self {
        MakeService {
            api_impl,
            marker: PhantomData
        }
    }
}

impl<T, C, Target> hyper::service::Service<Target> for MakeService<T, C> where
    T: Api<C> + Clone + Send + 'static,
    C: Has<XSpanIdString> + Has<Option<Authorization>> + Send + Sync + 'static
{
    type Response = Service<T, C>;
    type Error = crate::ServiceError;
    type Future = future::Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, target: Target) -> Self::Future {
        futures::future::ok(Service::new(
            self.api_impl.clone(),
        ))
    }
}

fn method_not_allowed() -> Result<Response<Body>, crate::ServiceError> {
    Ok(
        Response::builder().status(StatusCode::METHOD_NOT_ALLOWED)
            .body(Body::empty())
            .expect("Unable to create Method Not Allowed response")
    )
}

pub struct Service<T, C> where
    T: Api<C> + Clone + Send + 'static,
    C: Has<XSpanIdString> + Has<Option<Authorization>> + Send + Sync + 'static
{
    api_impl: T,
    marker: PhantomData<C>,
}

impl<T, C> Service<T, C> where
    T: Api<C> + Clone + Send + 'static,
    C: Has<XSpanIdString> + Has<Option<Authorization>> + Send + Sync + 'static
{
    pub fn new(api_impl: T) -> Self {
        Service {
            api_impl,
            marker: PhantomData
        }
    }
}

impl<T, C> Clone for Service<T, C> where
    T: Api<C> + Clone + Send + 'static,
    C: Has<XSpanIdString> + Has<Option<Authorization>> + Send + Sync + 'static
{
    fn clone(&self) -> Self {
        Service {
            api_impl: self.api_impl.clone(),
            marker: self.marker,
        }
    }
}

impl<T, C> hyper::service::Service<(Request<Body>, C)> for Service<T, C> where
    T: Api<C> + Clone + Send + Sync + 'static,
    C: Has<XSpanIdString> + Has<Option<Authorization>> + Send + Sync + 'static
{
    type Response = Response<Body>;
    type Error = crate::ServiceError;
    type Future = ServiceFuture;

    fn poll_ready(&mut self, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        self.api_impl.poll_ready(cx)
    }

    fn call(&mut self, req: (Request<Body>, C)) -> Self::Future { async fn run<T, C>(mut api_impl: T, req: (Request<Body>, C)) -> Result<Response<Body>, crate::ServiceError> where
        T: Api<C> + Clone + Send + 'static,
        C: Has<XSpanIdString> + Has<Option<Authorization>> + Send + Sync + 'static
    {
        let (request, context) = req;
        let (parts, body) = request.into_parts();
        let (method, uri, headers) = (parts.method, parts.uri, parts.headers);
        let path = paths::GLOBAL_REGEX_SET.matches(uri.path());

        match method {

            // CreateClaim - POST /v1/claims
            hyper::Method::POST if path.matched(paths::ID_V1_CLAIMS) => {
                {
                    let authorization = match *(&context as &dyn Has<Option<Authorization>>).get() {
                        Some(ref authorization) => authorization,
                        None => return Ok(Response::builder()
                                                .status(StatusCode::FORBIDDEN)
                                                .body(Body::from("Unauthenticated"))
                                                .expect("Unable to create Authentication Forbidden response")),
                    };
                }

                // Body parameters (note that non-required body parameters will ignore garbage
                // values, rather than causing a 400 response). Produce warning header and logs for
                // any unused fields.
                let result = body.into_raw().await;
                match result {
                            Ok(body) => {
                                let mut unused_elements = Vec::new();
                                let param_claim_request: Option<ClaimRequest> = if !body.is_empty() {
                                    let deserializer = &mut serde_json::Deserializer::from_slice(&body);
                                    match serde_ignored::deserialize(deserializer, |path| {
                                            warn!("Ignoring unknown field in body: {}", path);
                                            unused_elements.push(path.to_string());
                                    }) {
                                        Ok(param_claim_request) => param_claim_request,
                                        Err(e) => return Ok(Response::builder()
                                                        .status(StatusCode::BAD_REQUEST)
                                                        .body(Body::from(format!("Couldn't parse body parameter ClaimRequest - doesn't match schema: {}", e)))
                                                        .expect("Unable to create Bad Request response for invalid body parameter ClaimRequest due to schema")),
                                    }
                                } else {
                                    None
                                };
                                let param_claim_request = match param_claim_request {
                                    Some(param_claim_request) => param_claim_request,
                                    None => return Ok(Response::builder()
                                                        .status(StatusCode::BAD_REQUEST)
                                                        .body(Body::from("Missing required body parameter ClaimRequest"))
                                                        .expect("Unable to create Bad Request response for missing body parameter ClaimRequest")),
                                };

                                let result = api_impl.create_claim(
                                            param_claim_request,
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        if !unused_elements.is_empty() {
                                            response.headers_mut().insert(
                                                HeaderName::from_static("warning"),
                                                HeaderValue::from_str(format!("Ignoring unknown fields in body: {:?}", unused_elements).as_str())
                                                    .expect("Unable to create Warning header value"));
                                        }

                                        match result {
                                            Ok(rsp) => match rsp {
                                                CreateClaimResponse::Success
                                                    (body)
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(201).expect("Unable to turn 201 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_str("application/links+json")
                                                            .expect("Unable to create Content-Type header for CREATE_CLAIM_SUCCESS"));
                                                    let body = body;
                                                    *response.body_mut() = Body::from(body);
                                                },
                                                CreateClaimResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");
                                                },
                                                CreateClaimResponse::Forbidden
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(403).expect("Unable to turn 403 into a StatusCode");
                                                },
                                                CreateClaimResponse::AlreadyClaimed
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(409).expect("Unable to turn 409 into a StatusCode");
                                                },
                                            },
                                            Err(ApiError::NotImplementedError(_)) => {
                                                *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
                                                *response.body_mut() = Body::from(IMPLEMENTATION_NOT_YET_AVAILABLE_ERROR_STRING);
                                            },
                                            // Application code returned an error. This should not happen, as the implementation should return a valid response.
                                            Err(ApiError::UnknownApiError(error_message)) => {
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from(format!("An internal error occurred {}", error_message));
                                            }
                                        }

                                        Ok(response)
                            },
                            Err(e) => Ok(Response::builder()
                                                .status(StatusCode::BAD_REQUEST)
                                                .body(Body::from(format!("Couldn't read body parameter ClaimRequest: {}", e)))
                                                .expect("Unable to create Bad Request response due to unable to read body parameter ClaimRequest")),
                        }
            },

            // CreateInvite - POST /v1/invites
            hyper::Method::POST if path.matched(paths::ID_V1_INVITES) => {
                {
                    let authorization = match *(&context as &dyn Has<Option<Authorization>>).get() {
                        Some(ref authorization) => authorization,
                        None => return Ok(Response::builder()
                                                .status(StatusCode::FORBIDDEN)
                                                .body(Body::from("Unauthenticated"))
                                                .expect("Unable to create Authentication Forbidden response")),
                    };
                }

                // Body parameters (note that non-required body parameters will ignore garbage
                // values, rather than causing a 400 response). Produce warning header and logs for
                // any unused fields.
                let result = body.into_raw().await;
                match result {
                            Ok(body) => {
                                let mut unused_elements = Vec::new();
                                let param_invite: Option<Invite> = if !body.is_empty() {
                                    let deserializer = &mut serde_json::Deserializer::from_slice(&body);
                                    match serde_ignored::deserialize(deserializer, |path| {
                                            warn!("Ignoring unknown field in body: {}", path);
                                            unused_elements.push(path.to_string());
                                    }) {
                                        Ok(param_invite) => param_invite,
                                        Err(e) => return Ok(Response::builder()
                                                        .status(StatusCode::BAD_REQUEST)
                                                        .body(Body::from(format!("Couldn't parse body parameter Invite - doesn't match schema: {}", e)))
                                                        .expect("Unable to create Bad Request response for invalid body parameter Invite due to schema")),
                                    }
                                } else {
                                    None
                                };
                                let param_invite = match param_invite {
                                    Some(param_invite) => param_invite,
                                    None => return Ok(Response::builder()
                                                        .status(StatusCode::BAD_REQUEST)
                                                        .body(Body::from("Missing required body parameter Invite"))
                                                        .expect("Unable to create Bad Request response for missing body parameter Invite")),
                                };

                                let result = api_impl.create_invite(
                                            param_invite,
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        if !unused_elements.is_empty() {
                                            response.headers_mut().insert(
                                                HeaderName::from_static("warning"),
                                                HeaderValue::from_str(format!("Ignoring unknown fields in body: {:?}", unused_elements).as_str())
                                                    .expect("Unable to create Warning header value"));
                                        }

                                        match result {
                                            Ok(rsp) => match rsp {
                                                CreateInviteResponse::Success
                                                    (body)
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(201).expect("Unable to turn 201 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_str("application/links+json")
                                                            .expect("Unable to create Content-Type header for CREATE_INVITE_SUCCESS"));
                                                    let body = body;
                                                    *response.body_mut() = Body::from(body);
                                                },
                                                CreateInviteResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");
                                                },
                                                CreateInviteResponse::Forbidden
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(403).expect("Unable to turn 403 into a StatusCode");
                                                },
                                            },
                                            Err(ApiError::NotImplementedError(_)) => {
                                                *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
                                                *response.body_mut() = Body::from(IMPLEMENTATION_NOT_YET_AVAILABLE_ERROR_STRING);
                                            },
                                            // Application code returned an error. This should not happen, as the implementation should return a valid response.
                                            Err(ApiError::UnknownApiError(error_message)) => {
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from(format!("An internal error occurred {}", error_message));
                                            }
                                        }

                                        Ok(response)
                            },
                            Err(e) => Ok(Response::builder()
                                                .status(StatusCode::BAD_REQUEST)
                                                .body(Body::from(format!("Couldn't read body parameter Invite: {}", e)))
                                                .expect("Unable to create Bad Request response due to unable to read body parameter Invite")),
                        }
            },

            // CreateRecord - POST /v1/records
            hyper::Method::POST if path.matched(paths::ID_V1_RECORDS) => {
                {
                    let authorization = match *(&context as &dyn Has<Option<Authorization>>).get() {
                        Some(ref authorization) => authorization,
                        None => return Ok(Response::builder()
                                                .status(StatusCode::FORBIDDEN)
                                                .body(Body::from("Unauthenticated"))
                                                .expect("Unable to create Authentication Forbidden response")),
                    };
                }

                // Body parameters (note that non-required body parameters will ignore garbage
                // values, rather than causing a 400 response). Produce warning header and logs for
                // any unused fields.
                let result = body.into_raw().await;
                match result {
                            Ok(body) => {
                                let mut unused_elements = Vec::new();
                                let param_access_record: Option<AccessRecord> = if !body.is_empty() {
                                    let deserializer = &mut serde_json::Deserializer::from_slice(&body);
                                    match serde_ignored::deserialize(deserializer, |path| {
                                            warn!("Ignoring unknown field in body: {}", path);
                                            unused_elements.push(path.to_string());
                                    }) {
                                        Ok(param_access_record) => param_access_record,
                                        Err(e) => return Ok(Response::builder()
                                                        .status(StatusCode::BAD_REQUEST)
                                                        .body(Body::from(format!("Couldn't parse body parameter AccessRecord - doesn't match schema: {}", e)))
                                                        .expect("Unable to create Bad Request response for invalid body parameter AccessRecord due to schema")),
                                    }
                                } else {
                                    None
                                };
                                let param_access_record = match param_access_record {
                                    Some(param_access_record) => param_access_record,
                                    None => return Ok(Response::builder()
                                                        .status(StatusCode::BAD_REQUEST)
                                                        .body(Body::from("Missing required body parameter AccessRecord"))
                                                        .expect("Unable to create Bad Request response for missing body parameter AccessRecord")),
                                };

                                let result = api_impl.create_record(
                                            param_access_record,
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        if !unused_elements.is_empty() {
                                            response.headers_mut().insert(
                                                HeaderName::from_static("warning"),
                                                HeaderValue::from_str(format!("Ignoring unknown fields in body: {:?}", unused_elements).as_str())
                                                    .expect("Unable to create Warning header value"));
                                        }

                                        match result {
                                            Ok(rsp) => match rsp {
                                                CreateRecordResponse::Success
                                                    {
                                                        body,
                                                        last_modified
                                                    }
                                                => {
                                                    if let Some(last_modified) = last_modified {
                                                    let last_modified = match header::IntoHeaderValue(last_modified).try_into() {
                                                        Ok(val) => val,
                                                        Err(e) => {
                                                            return Ok(Response::builder()
                                                                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                                                                    .body(Body::from(format!("An internal server error occurred handling last_modified header - {}", e)))
                                                                    .expect("Unable to create Internal Server Error for invalid response header"))
                                                        }
                                                    };

                                                    response.headers_mut().insert(
                                                        HeaderName::from_static("last-modified"),
                                                        last_modified
                                                    );
                                                    }
                                                    *response.status_mut() = StatusCode::from_u16(201).expect("Unable to turn 201 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_str("application/links+json")
                                                            .expect("Unable to create Content-Type header for CREATE_RECORD_SUCCESS"));
                                                    let body = body;
                                                    *response.body_mut() = Body::from(body);
                                                },
                                                CreateRecordResponse::TheSizeOfTheRecordIsLargerThanAllowed => {
                                                    return Ok(Response::builder().status(StatusCode::PAYLOAD_TOO_LARGE).body(Body::from("The size of the access record is too large."))?);
                                                },
                                                CreateRecordResponse::AccessRecordAlreadyExists => {
                                                    return Ok(Response::builder().status(StatusCode::CONFLICT).body(Body::from("Record already exists"))?);
                                                },
                                                CreateRecordResponse::Unauthorized => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");
                                                },
                                                CreateRecordResponse::Forbidden
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(403).expect("Unable to turn 403 into a StatusCode");
                                                },
                                            },
                                            Err(ApiError::NotImplementedError(_)) => {
                                                *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
                                                *response.body_mut() = Body::from(IMPLEMENTATION_NOT_YET_AVAILABLE_ERROR_STRING);
                                            },
                                            // Application code returned an error. This should not happen, as the implementation should return a valid response.
                                            Err(ApiError::UnknownApiError(error_message)) => {
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from(format!("An internal error occurred {}", error_message));
                                            }
                                        }

                                        Ok(response)
                            },
                            Err(e) => Ok(Response::builder()
                                                .status(StatusCode::BAD_REQUEST)
                                                .body(Body::from(format!("Couldn't read body parameter AccessRecord: {}", e)))
                                                .expect("Unable to create Bad Request response due to unable to read body parameter AccessRecord")),
                        }
            },

            // CreateRequest - POST /v1/requests
            hyper::Method::POST if path.matched(paths::ID_V1_REQUESTS) => {
                {
                    let authorization = match *(&context as &dyn Has<Option<Authorization>>).get() {
                        Some(ref authorization) => authorization,
                        None => return Ok(Response::builder()
                                                .status(StatusCode::FORBIDDEN)
                                                .body(Body::from("Unauthenticated"))
                                                .expect("Unable to create Authentication Forbidden response")),
                    };
                }

                // Body parameters (note that non-required body parameters will ignore garbage
                // values, rather than causing a 400 response). Produce warning header and logs for
                // any unused fields.
                let result = body.into_raw().await;
                match result {
                            Ok(body) => {
                                let mut unused_elements = Vec::new();
                                let param_access_request: Option<AccessRequest> = if !body.is_empty() {
                                    let deserializer = &mut serde_json::Deserializer::from_slice(&body);
                                    match serde_ignored::deserialize(deserializer, |path| {
                                            warn!("Ignoring unknown field in body: {}", path);
                                            unused_elements.push(path.to_string());
                                    }) {
                                        Ok(param_access_request) => param_access_request,
                                        Err(e) => return Ok(Response::builder()
                                                        .status(StatusCode::BAD_REQUEST)
                                                        .body(Body::from(format!("Couldn't parse body parameter AccessRequest - doesn't match schema: {}", e)))
                                                        .expect("Unable to create Bad Request response for invalid body parameter AccessRequest due to schema")),
                                    }
                                } else {
                                    None
                                };
                                let param_access_request = match param_access_request {
                                    Some(param_access_request) => param_access_request,
                                    None => return Ok(Response::builder()
                                                        .status(StatusCode::BAD_REQUEST)
                                                        .body(Body::from("Missing required body parameter AccessRequest"))
                                                        .expect("Unable to create Bad Request response for missing body parameter AccessRequest")),
                                };

                                let result = api_impl.create_request(
                                            param_access_request,
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        if !unused_elements.is_empty() {
                                            response.headers_mut().insert(
                                                HeaderName::from_static("warning"),
                                                HeaderValue::from_str(format!("Ignoring unknown fields in body: {:?}", unused_elements).as_str())
                                                    .expect("Unable to create Warning header value"));
                                        }

                                        match result {
                                            Ok(rsp) => match rsp {
                                                CreateRequestResponse::Success
                                                    (body)
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(201).expect("Unable to turn 201 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_str("application/links+json")
                                                            .expect("Unable to create Content-Type header for CREATE_REQUEST_SUCCESS"));
                                                    let body = body;
                                                    *response.body_mut() = Body::from(body);
                                                },
                                                CreateRequestResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");
                                                },
                                                CreateRequestResponse::Forbidden
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(403).expect("Unable to turn 403 into a StatusCode");
                                                },
                                                CreateRequestResponse::UnprocessableEntity
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(422).expect("Unable to turn 422 into a StatusCode");
                                                },
                                            },
                                            Err(ApiError::NotImplementedError(_)) => {
                                                *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
                                                *response.body_mut() = Body::from(IMPLEMENTATION_NOT_YET_AVAILABLE_ERROR_STRING);
                                            },
                                            // Application code returned an error. This should not happen, as the implementation should return a valid response.
                                            Err(ApiError::UnknownApiError(error_message)) => {
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from(format!("An internal error occurred {}", error_message));
                                            }
                                        }

                                        Ok(response)
                            },
                            Err(e) => Ok(Response::builder()
                                                .status(StatusCode::BAD_REQUEST)
                                                .body(Body::from(format!("Couldn't read body parameter AccessRequest: {}", e)))
                                                .expect("Unable to create Bad Request response due to unable to read body parameter AccessRequest")),
                        }
            },

            // DeleteInvite - DELETE /v1/invites/{inviteId}
            hyper::Method::DELETE if path.matched(paths::ID_V1_INVITES_INVITEID) => {
                {
                    let authorization = match *(&context as &dyn Has<Option<Authorization>>).get() {
                        Some(ref authorization) => authorization,
                        None => return Ok(Response::builder()
                                                .status(StatusCode::FORBIDDEN)
                                                .body(Body::from("Unauthenticated"))
                                                .expect("Unable to create Authentication Forbidden response")),
                    };
                }

                // Path parameters
                let path: &str = uri.path();
                let path_params =
                    paths::REGEX_V1_INVITES_INVITEID
                    .captures(path)
                    .unwrap_or_else(||
                        panic!("Path {} matched RE V1_INVITES_INVITEID in set but failed match against \"{}\"", path, paths::REGEX_V1_INVITES_INVITEID.as_str())
                    );

                let param_invite_id = match percent_encoding::percent_decode(path_params["inviteId"].as_bytes()).decode_utf8() {
                    Ok(param_invite_id) => match param_invite_id.parse::<String>() {
                        Ok(param_invite_id) => param_invite_id,
                        Err(e) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't parse path parameter inviteId: {}", e)))
                                        .expect("Unable to create Bad Request response for invalid path parameter")),
                    },
                    Err(_) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't percent-decode path parameter as UTF-8: {}", &path_params["inviteId"])))
                                        .expect("Unable to create Bad Request response for invalid percent decode"))
                };

                                let result = api_impl.delete_invite(
                                            param_invite_id,
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        match result {
                                            Ok(rsp) => match rsp {
                                                DeleteInviteResponse::Success
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(204).expect("Unable to turn 204 into a StatusCode");
                                                },
                                                DeleteInviteResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");
                                                },
                                                DeleteInviteResponse::Forbidden
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(403).expect("Unable to turn 403 into a StatusCode");
                                                },
                                                DeleteInviteResponse::NotFound
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(404).expect("Unable to turn 404 into a StatusCode");
                                                },
                                            },
                                            Err(ApiError::NotImplementedError(_)) => {
                                                *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
                                                *response.body_mut() = Body::from(IMPLEMENTATION_NOT_YET_AVAILABLE_ERROR_STRING);
                                            },
                                            // Application code returned an error. This should not happen, as the implementation should return a valid response.
                                            Err(ApiError::UnknownApiError(error_message)) => {
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from(format!("An internal error occurred {}", error_message));
                                            }
                                        }

                                        Ok(response)
            },

            // DeleteRecord - DELETE /v1/records/{recordId}
            hyper::Method::DELETE if path.matched(paths::ID_V1_RECORDS_RECORDID) => {
                {
                    let authorization = match *(&context as &dyn Has<Option<Authorization>>).get() {
                        Some(ref authorization) => authorization,
                        None => return Ok(Response::builder()
                                                .status(StatusCode::FORBIDDEN)
                                                .body(Body::from("Unauthenticated"))
                                                .expect("Unable to create Authentication Forbidden response")),
                    };
                }

                // Path parameters
                let path: &str = uri.path();
                let path_params =
                    paths::REGEX_V1_RECORDS_RECORDID
                    .captures(path)
                    .unwrap_or_else(||
                        panic!("Path {} matched RE V1_RECORDS_RECORDID in set but failed match against \"{}\"", path, paths::REGEX_V1_RECORDS_RECORDID.as_str())
                    );

                let param_record_id = match percent_encoding::percent_decode(path_params["recordId"].as_bytes()).decode_utf8() {
                    Ok(param_record_id) => match param_record_id.parse::<String>() {
                        Ok(param_record_id) => param_record_id,
                        Err(e) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't parse path parameter recordId: {}", e)))
                                        .expect("Unable to create Bad Request response for invalid path parameter")),
                    },
                    Err(_) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't percent-decode path parameter as UTF-8: {}", &path_params["recordId"])))
                                        .expect("Unable to create Bad Request response for invalid percent decode"))
                };

                                let result = api_impl.delete_record(
                                            param_record_id,
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        match result {
                                            Ok(rsp) => match rsp {
                                                DeleteRecordResponse::Success
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(204).expect("Unable to turn 204 into a StatusCode");
                                                },
                                                DeleteRecordResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");
                                                },
                                                DeleteRecordResponse::Forbidden
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(403).expect("Unable to turn 403 into a StatusCode");
                                                },
                                                DeleteRecordResponse::NotFound
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(404).expect("Unable to turn 404 into a StatusCode");
                                                },
                                            },
                                            Err(ApiError::NotImplementedError(_)) => {
                                                *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
                                                *response.body_mut() = Body::from(IMPLEMENTATION_NOT_YET_AVAILABLE_ERROR_STRING);
                                            },
                                            // Application code returned an error. This should not happen, as the implementation should return a valid response.
                                            Err(ApiError::UnknownApiError(error_message)) => {
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from(format!("An internal error occurred {}", error_message));
                                            }
                                        }

                                        Ok(response)
            },

            // DeleteRequest - DELETE /v1/requests/{requestId}
            hyper::Method::DELETE if path.matched(paths::ID_V1_REQUESTS_REQUESTID) => {
                {
                    let authorization = match *(&context as &dyn Has<Option<Authorization>>).get() {
                        Some(ref authorization) => authorization,
                        None => return Ok(Response::builder()
                                                .status(StatusCode::FORBIDDEN)
                                                .body(Body::from("Unauthenticated"))
                                                .expect("Unable to create Authentication Forbidden response")),
                    };
                }

                // Path parameters
                let path: &str = uri.path();
                let path_params =
                    paths::REGEX_V1_REQUESTS_REQUESTID
                    .captures(path)
                    .unwrap_or_else(||
                        panic!("Path {} matched RE V1_REQUESTS_REQUESTID in set but failed match against \"{}\"", path, paths::REGEX_V1_REQUESTS_REQUESTID.as_str())
                    );

                let param_request_id = match percent_encoding::percent_decode(path_params["requestId"].as_bytes()).decode_utf8() {
                    Ok(param_request_id) => match param_request_id.parse::<String>() {
                        Ok(param_request_id) => param_request_id,
                        Err(e) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't parse path parameter requestId: {}", e)))
                                        .expect("Unable to create Bad Request response for invalid path parameter")),
                    },
                    Err(_) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't percent-decode path parameter as UTF-8: {}", &path_params["requestId"])))
                                        .expect("Unable to create Bad Request response for invalid percent decode"))
                };

                                let result = api_impl.delete_request(
                                            param_request_id,
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        match result {
                                            Ok(rsp) => match rsp {
                                                DeleteRequestResponse::Success
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(204).expect("Unable to turn 204 into a StatusCode");
                                                },
                                                DeleteRequestResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");
                                                },
                                                DeleteRequestResponse::Forbidden
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(403).expect("Unable to turn 403 into a StatusCode");
                                                },
                                                DeleteRequestResponse::NotFound
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(404).expect("Unable to turn 404 into a StatusCode");
                                                },
                                            },
                                            Err(ApiError::NotImplementedError(_)) => {
                                                *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
                                                *response.body_mut() = Body::from(IMPLEMENTATION_NOT_YET_AVAILABLE_ERROR_STRING);
                                            },
                                            // Application code returned an error. This should not happen, as the implementation should return a valid response.
                                            Err(ApiError::UnknownApiError(error_message)) => {
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from(format!("An internal error occurred {}", error_message));
                                            }
                                        }

                                        Ok(response)
            },

            // GetRecord - GET /v1/records/{recordId}
            hyper::Method::GET if path.matched(paths::ID_V1_RECORDS_RECORDID) => {
                {
                    let authorization = match *(&context as &dyn Has<Option<Authorization>>).get() {
                        Some(ref authorization) => authorization,
                        None => return Ok(Response::builder()
                                                .status(StatusCode::FORBIDDEN)
                                                .body(Body::from("Unauthenticated"))
                                                .expect("Unable to create Authentication Forbidden response")),
                    };
                }

                // Path parameters
                let path: &str = uri.path();
                let path_params =
                    paths::REGEX_V1_RECORDS_RECORDID
                    .captures(path)
                    .unwrap_or_else(||
                        panic!("Path {} matched RE V1_RECORDS_RECORDID in set but failed match against \"{}\"", path, paths::REGEX_V1_RECORDS_RECORDID.as_str())
                    );

                let param_record_id = match percent_encoding::percent_decode(path_params["recordId"].as_bytes()).decode_utf8() {
                    Ok(param_record_id) => match param_record_id.parse::<String>() {
                        Ok(param_record_id) => param_record_id,
                        Err(e) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't parse path parameter recordId: {}", e)))
                                        .expect("Unable to create Bad Request response for invalid path parameter")),
                    },
                    Err(_) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't percent-decode path parameter as UTF-8: {}", &path_params["recordId"])))
                                        .expect("Unable to create Bad Request response for invalid percent decode"))
                };

                                let result = api_impl.get_record(
                                            param_record_id,
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        match result {
                                            Ok(rsp) => match rsp {
                                                GetRecordResponse::Success
                                                    {
                                                        body,
                                                        last_modified
                                                    }
                                                => {
                                                    if let Some(last_modified) = last_modified {
                                                    let last_modified = match header::IntoHeaderValue(last_modified).try_into() {
                                                        Ok(val) => val,
                                                        Err(e) => {
                                                            return Ok(Response::builder()
                                                                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                                                                    .body(Body::from(format!("An internal server error occurred handling last_modified header - {}", e)))
                                                                    .expect("Unable to create Internal Server Error for invalid response header"))
                                                        }
                                                    };

                                                    response.headers_mut().insert(
                                                        HeaderName::from_static("last-modified"),
                                                        last_modified
                                                    );
                                                    }
                                                    *response.status_mut() = StatusCode::from_u16(200).expect("Unable to turn 200 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_str("application/links+json")
                                                            .expect("Unable to create Content-Type header for GET_RECORD_SUCCESS"));
                                                    let body = body;
                                                    *response.body_mut() = Body::from(body);
                                                },
                                                GetRecordResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");
                                                },
                                                GetRecordResponse::Forbidden
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(403).expect("Unable to turn 403 into a StatusCode");
                                                },
                                                GetRecordResponse::NotFound
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(404).expect("Unable to turn 404 into a StatusCode");
                                                },
                                            },
                                            Err(ApiError::NotImplementedError(_)) => {
                                                *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
                                                *response.body_mut() = Body::from(IMPLEMENTATION_NOT_YET_AVAILABLE_ERROR_STRING);
                                            },
                                            // Application code returned an error. This should not happen, as the implementation should return a valid response.
                                            Err(ApiError::UnknownApiError(error_message)) => {
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from(format!("An internal error occurred {}", error_message));
                                            }
                                        }

                                        Ok(response)
            },

            // GetRecords - GET /v1/records
            hyper::Method::GET if path.matched(paths::ID_V1_RECORDS) => {
                {
                    let authorization = match *(&context as &dyn Has<Option<Authorization>>).get() {
                        Some(ref authorization) => authorization,
                        None => return Ok(Response::builder()
                                                .status(StatusCode::FORBIDDEN)
                                                .body(Body::from("Unauthenticated"))
                                                .expect("Unable to create Authentication Forbidden response")),
                    };
                }

                // Query parameters (note that non-required or collection query parameters will ignore garbage values, rather than causing a 400 response)
                let query_params = form_urlencoded::parse(uri.query().unwrap_or_default().as_bytes()).collect::<Vec<_>>();
                let param_limit = query_params.iter().filter(|e| e.0 == "limit").map(|e| e.1.clone())
                    .next();
                let param_limit = match param_limit {
                    Some(param_limit) => {
                        let param_limit =
                            <i32 as std::str::FromStr>::from_str
                                (&param_limit);
                        match param_limit {
                            Ok(param_limit) => Some(param_limit),
                            Err(e) => return Ok(Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body(Body::from(format!("Couldn't parse query parameter limit - doesn't match schema: {}", e)))
                                .expect("Unable to create Bad Request response for invalid query parameter limit")),
                        }
                    },
                    None => None,
                };
                let param_cursor = query_params.iter().filter(|e| e.0 == "cursor").map(|e| e.1.clone())
                    .next();
                let param_cursor = match param_cursor {
                    Some(param_cursor) => {
                        let param_cursor =
                            <String as std::str::FromStr>::from_str
                                (&param_cursor);
                        match param_cursor {
                            Ok(param_cursor) => Some(param_cursor),
                            Err(e) => return Ok(Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body(Body::from(format!("Couldn't parse query parameter cursor - doesn't match schema: {}", e)))
                                .expect("Unable to create Bad Request response for invalid query parameter cursor")),
                        }
                    },
                    None => None,
                };
                let param_filter = query_params.iter().filter(|e| e.0 == "filter").map(|e| e.1.clone())
                    .next();
                let param_filter = match param_filter {
                    Some(param_filter) => {
                        let param_filter =
                            <String as std::str::FromStr>::from_str
                                (&param_filter);
                        match param_filter {
                            Ok(param_filter) => Some(param_filter),
                            Err(e) => return Ok(Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body(Body::from(format!("Couldn't parse query parameter filter - doesn't match schema: {}", e)))
                                .expect("Unable to create Bad Request response for invalid query parameter filter")),
                        }
                    },
                    None => None,
                };
                let param_status = query_params.iter().filter(|e| e.0 == "status").map(|e| e.1.clone())
                    .next();
                let param_status = match param_status {
                    Some(param_status) => {
                        let param_status =
                            <String as std::str::FromStr>::from_str
                                (&param_status);
                        match param_status {
                            Ok(param_status) => Some(param_status),
                            Err(e) => return Ok(Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body(Body::from(format!("Couldn't parse query parameter status - doesn't match schema: {}", e)))
                                .expect("Unable to create Bad Request response for invalid query parameter status")),
                        }
                    },
                    None => None,
                };

                                let result = api_impl.get_records(
                                            param_limit,
                                            param_cursor,
                                            param_filter,
                                            param_status,
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        match result {
                                            Ok(rsp) => match rsp {
                                                GetRecordsResponse::Success
                                                    (body)
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(200).expect("Unable to turn 200 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_str("application/links+json")
                                                            .expect("Unable to create Content-Type header for GET_RECORDS_SUCCESS"));
                                                    let body = body;
                                                    *response.body_mut() = Body::from(body);
                                                },
                                                GetRecordsResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");
                                                },
                                                GetRecordsResponse::Forbidden
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(403).expect("Unable to turn 403 into a StatusCode");
                                                },
                                            },
                                            Err(ApiError::NotImplementedError(_)) => {
                                                *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
                                                *response.body_mut() = Body::from(IMPLEMENTATION_NOT_YET_AVAILABLE_ERROR_STRING);
                                            },
                                            // Application code returned an error. This should not happen, as the implementation should return a valid response.
                                            Err(ApiError::UnknownApiError(error_message)) => {
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from(format!("An internal error occurred {}", error_message));
                                            }
                                        }

                                        Ok(response)
            },

            // GetRequest - GET /v1/requests/{requestId}
            hyper::Method::GET if path.matched(paths::ID_V1_REQUESTS_REQUESTID) => {
                {
                    let authorization = match *(&context as &dyn Has<Option<Authorization>>).get() {
                        Some(ref authorization) => authorization,
                        None => return Ok(Response::builder()
                                                .status(StatusCode::FORBIDDEN)
                                                .body(Body::from("Unauthenticated"))
                                                .expect("Unable to create Authentication Forbidden response")),
                    };
                }

                // Path parameters
                let path: &str = uri.path();
                let path_params =
                    paths::REGEX_V1_REQUESTS_REQUESTID
                    .captures(path)
                    .unwrap_or_else(||
                        panic!("Path {} matched RE V1_REQUESTS_REQUESTID in set but failed match against \"{}\"", path, paths::REGEX_V1_REQUESTS_REQUESTID.as_str())
                    );

                let param_request_id = match percent_encoding::percent_decode(path_params["requestId"].as_bytes()).decode_utf8() {
                    Ok(param_request_id) => match param_request_id.parse::<String>() {
                        Ok(param_request_id) => param_request_id,
                        Err(e) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't parse path parameter requestId: {}", e)))
                                        .expect("Unable to create Bad Request response for invalid path parameter")),
                    },
                    Err(_) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't percent-decode path parameter as UTF-8: {}", &path_params["requestId"])))
                                        .expect("Unable to create Bad Request response for invalid percent decode"))
                };

                                let result = api_impl.get_request(
                                            param_request_id,
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        match result {
                                            Ok(rsp) => match rsp {
                                                GetRequestResponse::Success
                                                    (body)
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(200).expect("Unable to turn 200 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_str("application/links+json")
                                                            .expect("Unable to create Content-Type header for GET_REQUEST_SUCCESS"));
                                                    let body = body;
                                                    *response.body_mut() = Body::from(body);
                                                },
                                                GetRequestResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");
                                                },
                                                GetRequestResponse::Forbidden
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(403).expect("Unable to turn 403 into a StatusCode");
                                                },
                                                GetRequestResponse::NotFound
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(404).expect("Unable to turn 404 into a StatusCode");
                                                },
                                            },
                                            Err(ApiError::NotImplementedError(_)) => {
                                                *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
                                                *response.body_mut() = Body::from(IMPLEMENTATION_NOT_YET_AVAILABLE_ERROR_STRING);
                                            },
                                            // Application code returned an error. This should not happen, as the implementation should return a valid response.
                                            Err(ApiError::UnknownApiError(error_message)) => {
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from(format!("An internal error occurred {}", error_message));
                                            }
                                        }

                                        Ok(response)
            },

            // GetRequests - GET /v1/requests
            hyper::Method::GET if path.matched(paths::ID_V1_REQUESTS) => {
                {
                    let authorization = match *(&context as &dyn Has<Option<Authorization>>).get() {
                        Some(ref authorization) => authorization,
                        None => return Ok(Response::builder()
                                                .status(StatusCode::FORBIDDEN)
                                                .body(Body::from("Unauthenticated"))
                                                .expect("Unable to create Authentication Forbidden response")),
                    };
                }

                // Query parameters (note that non-required or collection query parameters will ignore garbage values, rather than causing a 400 response)
                let query_params = form_urlencoded::parse(uri.query().unwrap_or_default().as_bytes()).collect::<Vec<_>>();
                let param_limit = query_params.iter().filter(|e| e.0 == "limit").map(|e| e.1.clone())
                    .next();
                let param_limit = match param_limit {
                    Some(param_limit) => {
                        let param_limit =
                            <i32 as std::str::FromStr>::from_str
                                (&param_limit);
                        match param_limit {
                            Ok(param_limit) => Some(param_limit),
                            Err(e) => return Ok(Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body(Body::from(format!("Couldn't parse query parameter limit - doesn't match schema: {}", e)))
                                .expect("Unable to create Bad Request response for invalid query parameter limit")),
                        }
                    },
                    None => None,
                };
                let param_cursor = query_params.iter().filter(|e| e.0 == "cursor").map(|e| e.1.clone())
                    .next();
                let param_cursor = match param_cursor {
                    Some(param_cursor) => {
                        let param_cursor =
                            <String as std::str::FromStr>::from_str
                                (&param_cursor);
                        match param_cursor {
                            Ok(param_cursor) => Some(param_cursor),
                            Err(e) => return Ok(Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body(Body::from(format!("Couldn't parse query parameter cursor - doesn't match schema: {}", e)))
                                .expect("Unable to create Bad Request response for invalid query parameter cursor")),
                        }
                    },
                    None => None,
                };
                let param_status = query_params.iter().filter(|e| e.0 == "status").map(|e| e.1.clone())
                    .next();
                let param_status = match param_status {
                    Some(param_status) => {
                        let param_status =
                            <String as std::str::FromStr>::from_str
                                (&param_status);
                        match param_status {
                            Ok(param_status) => Some(param_status),
                            Err(e) => return Ok(Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body(Body::from(format!("Couldn't parse query parameter status - doesn't match schema: {}", e)))
                                .expect("Unable to create Bad Request response for invalid query parameter status")),
                        }
                    },
                    None => None,
                };

                                let result = api_impl.get_requests(
                                            param_limit,
                                            param_cursor,
                                            param_status,
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        match result {
                                            Ok(rsp) => match rsp {
                                                GetRequestsResponse::Success
                                                    (body)
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(200).expect("Unable to turn 200 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_str("application/links+json")
                                                            .expect("Unable to create Content-Type header for GET_REQUESTS_SUCCESS"));
                                                    let body = body;
                                                    *response.body_mut() = Body::from(body);
                                                },
                                                GetRequestsResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");
                                                },
                                                GetRequestsResponse::Forbidden
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(403).expect("Unable to turn 403 into a StatusCode");
                                                },
                                            },
                                            Err(ApiError::NotImplementedError(_)) => {
                                                *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
                                                *response.body_mut() = Body::from(IMPLEMENTATION_NOT_YET_AVAILABLE_ERROR_STRING);
                                            },
                                            // Application code returned an error. This should not happen, as the implementation should return a valid response.
                                            Err(ApiError::UnknownApiError(error_message)) => {
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from(format!("An internal error occurred {}", error_message));
                                            }
                                        }

                                        Ok(response)
            },

            // RespondToAccessRequest - PATCH /v1/requests/{requestId}
            hyper::Method::PATCH if path.matched(paths::ID_V1_REQUESTS_REQUESTID) => {
                {
                    let authorization = match *(&context as &dyn Has<Option<Authorization>>).get() {
                        Some(ref authorization) => authorization,
                        None => return Ok(Response::builder()
                                                .status(StatusCode::FORBIDDEN)
                                                .body(Body::from("Unauthenticated"))
                                                .expect("Unable to create Authentication Forbidden response")),
                    };
                }

                // Path parameters
                let path: &str = uri.path();
                let path_params =
                    paths::REGEX_V1_REQUESTS_REQUESTID
                    .captures(path)
                    .unwrap_or_else(||
                        panic!("Path {} matched RE V1_REQUESTS_REQUESTID in set but failed match against \"{}\"", path, paths::REGEX_V1_REQUESTS_REQUESTID.as_str())
                    );

                let param_request_id = match percent_encoding::percent_decode(path_params["requestId"].as_bytes()).decode_utf8() {
                    Ok(param_request_id) => match param_request_id.parse::<String>() {
                        Ok(param_request_id) => param_request_id,
                        Err(e) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't parse path parameter requestId: {}", e)))
                                        .expect("Unable to create Bad Request response for invalid path parameter")),
                    },
                    Err(_) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't percent-decode path parameter as UTF-8: {}", &path_params["requestId"])))
                                        .expect("Unable to create Bad Request response for invalid percent decode"))
                };

                // Body parameters (note that non-required body parameters will ignore garbage
                // values, rather than causing a 400 response). Produce warning header and logs for
                // any unused fields.
                let result = body.into_raw().await;
                match result {
                            Ok(body) => {
                                let mut unused_elements = Vec::new();
                                let param_access_request_response: Option<AccessRequestResponse> = if !body.is_empty() {
                                    let deserializer = &mut serde_json::Deserializer::from_slice(&body);
                                    match serde_ignored::deserialize(deserializer, |path| {
                                            warn!("Ignoring unknown field in body: {}", path);
                                            unused_elements.push(path.to_string());
                                    }) {
                                        Ok(param_access_request_response) => param_access_request_response,
                                        Err(e) => return Ok(Response::builder()
                                                        .status(StatusCode::BAD_REQUEST)
                                                        .body(Body::from(format!("Couldn't parse body parameter AccessRequestResponse - doesn't match schema: {}", e)))
                                                        .expect("Unable to create Bad Request response for invalid body parameter AccessRequestResponse due to schema")),
                                    }
                                } else {
                                    None
                                };
                                let param_access_request_response = match param_access_request_response {
                                    Some(param_access_request_response) => param_access_request_response,
                                    None => return Ok(Response::builder()
                                                        .status(StatusCode::BAD_REQUEST)
                                                        .body(Body::from("Missing required body parameter AccessRequestResponse"))
                                                        .expect("Unable to create Bad Request response for missing body parameter AccessRequestResponse")),
                                };

                                let result = api_impl.respond_to_access_request(
                                            param_request_id,
                                            param_access_request_response,
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        if !unused_elements.is_empty() {
                                            response.headers_mut().insert(
                                                HeaderName::from_static("warning"),
                                                HeaderValue::from_str(format!("Ignoring unknown fields in body: {:?}", unused_elements).as_str())
                                                    .expect("Unable to create Warning header value"));
                                        }

                                        match result {
                                            Ok(rsp) => match rsp {
                                                RespondToAccessRequestResponse::Success
                                                    (body)
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(200).expect("Unable to turn 200 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_str("application/links+json")
                                                            .expect("Unable to create Content-Type header for RESPOND_TO_ACCESS_REQUEST_SUCCESS"));
                                                    let body = body;
                                                    *response.body_mut() = Body::from(body);
                                                },
                                                RespondToAccessRequestResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");
                                                },
                                                RespondToAccessRequestResponse::Forbidden
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(403).expect("Unable to turn 403 into a StatusCode");
                                                },
                                                RespondToAccessRequestResponse::NotFound
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(404).expect("Unable to turn 404 into a StatusCode");
                                                },
                                            },
                                            Err(ApiError::NotImplementedError(_)) => {
                                                *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
                                                *response.body_mut() = Body::from(IMPLEMENTATION_NOT_YET_AVAILABLE_ERROR_STRING);
                                            },
                                            // Application code returned an error. This should not happen, as the implementation should return a valid response.
                                            Err(ApiError::UnknownApiError(error_message)) => {
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from(format!("An internal error occurred {}", error_message));
                                            }
                                        }

                                        Ok(response)
                            },
                            Err(e) => Ok(Response::builder()
                                                .status(StatusCode::BAD_REQUEST)
                                                .body(Body::from(format!("Couldn't read body parameter AccessRequestResponse: {}", e)))
                                                .expect("Unable to create Bad Request response due to unable to read body parameter AccessRequestResponse")),
                        }
            },

            // RespondToInvite - PATCH /v1/invites/{inviteId}
            hyper::Method::PATCH if path.matched(paths::ID_V1_INVITES_INVITEID) => {
                {
                    let authorization = match *(&context as &dyn Has<Option<Authorization>>).get() {
                        Some(ref authorization) => authorization,
                        None => return Ok(Response::builder()
                                                .status(StatusCode::FORBIDDEN)
                                                .body(Body::from("Unauthenticated"))
                                                .expect("Unable to create Authentication Forbidden response")),
                    };
                }

                // Path parameters
                let path: &str = uri.path();
                let path_params =
                    paths::REGEX_V1_INVITES_INVITEID
                    .captures(path)
                    .unwrap_or_else(||
                        panic!("Path {} matched RE V1_INVITES_INVITEID in set but failed match against \"{}\"", path, paths::REGEX_V1_INVITES_INVITEID.as_str())
                    );

                let param_invite_id = match percent_encoding::percent_decode(path_params["inviteId"].as_bytes()).decode_utf8() {
                    Ok(param_invite_id) => match param_invite_id.parse::<String>() {
                        Ok(param_invite_id) => param_invite_id,
                        Err(e) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't parse path parameter inviteId: {}", e)))
                                        .expect("Unable to create Bad Request response for invalid path parameter")),
                    },
                    Err(_) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't percent-decode path parameter as UTF-8: {}", &path_params["inviteId"])))
                                        .expect("Unable to create Bad Request response for invalid percent decode"))
                };

                                let result = api_impl.respond_to_invite(
                                            param_invite_id,
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        match result {
                                            Ok(rsp) => match rsp {
                                                RespondToInviteResponse::Success
                                                    (body)
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(200).expect("Unable to turn 200 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_str("application/links+json")
                                                            .expect("Unable to create Content-Type header for RESPOND_TO_INVITE_SUCCESS"));
                                                    let body = body;
                                                    *response.body_mut() = Body::from(body);
                                                },
                                                RespondToInviteResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");
                                                },
                                                RespondToInviteResponse::Forbidden
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(403).expect("Unable to turn 403 into a StatusCode");
                                                },
                                                RespondToInviteResponse::NotFound
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(404).expect("Unable to turn 404 into a StatusCode");
                                                },
                                            },
                                            Err(ApiError::NotImplementedError(_)) => {
                                                *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
                                                *response.body_mut() = Body::from(IMPLEMENTATION_NOT_YET_AVAILABLE_ERROR_STRING);
                                            },
                                            // Application code returned an error. This should not happen, as the implementation should return a valid response.
                                            Err(ApiError::UnknownApiError(error_message)) => {
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from(format!("An internal error occurred {}", error_message));
                                            }
                                        }

                                        Ok(response)
            },

            // UpdateRecord - PUT /v1/records/{recordId}
            hyper::Method::PUT if path.matched(paths::ID_V1_RECORDS_RECORDID) => {
                {
                    let authorization = match *(&context as &dyn Has<Option<Authorization>>).get() {
                        Some(ref authorization) => authorization,
                        None => return Ok(Response::builder()
                                                .status(StatusCode::FORBIDDEN)
                                                .body(Body::from("Unauthenticated"))
                                                .expect("Unable to create Authentication Forbidden response")),
                    };
                }

                // Path parameters
                let path: &str = uri.path();
                let path_params =
                    paths::REGEX_V1_RECORDS_RECORDID
                    .captures(path)
                    .unwrap_or_else(||
                        panic!("Path {} matched RE V1_RECORDS_RECORDID in set but failed match against \"{}\"", path, paths::REGEX_V1_RECORDS_RECORDID.as_str())
                    );

                let param_record_id = match percent_encoding::percent_decode(path_params["recordId"].as_bytes()).decode_utf8() {
                    Ok(param_record_id) => match param_record_id.parse::<String>() {
                        Ok(param_record_id) => param_record_id,
                        Err(e) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't parse path parameter recordId: {}", e)))
                                        .expect("Unable to create Bad Request response for invalid path parameter")),
                    },
                    Err(_) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't percent-decode path parameter as UTF-8: {}", &path_params["recordId"])))
                                        .expect("Unable to create Bad Request response for invalid percent decode"))
                };

                // Header parameters
                let param_if_unmodified_since = headers.get(HeaderName::from_static("if-unmodified-since"));

                let param_if_unmodified_since = match param_if_unmodified_since {
                    Some(v) => match header::IntoHeaderValue::<String>::try_from((*v).clone()) {
                        Ok(result) =>
                            Some(result.0),
                        Err(err) => {
                            return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Invalid header If-Unmodified-Since - {}", err)))
                                        .expect("Unable to create Bad Request response for invalid header If-Unmodified-Since"));

                        },
                    },
                    None => {
                        None
                    }
                };

                // Body parameters (note that non-required body parameters will ignore garbage
                // values, rather than causing a 400 response). Produce warning header and logs for
                // any unused fields.
                let result = body.into_raw().await;
                match result {
                            Ok(body) => {
                                let mut unused_elements = Vec::new();
                                let param_access_record: Option<AccessRecord> = if !body.is_empty() {
                                    let deserializer = &mut serde_json::Deserializer::from_slice(&body);
                                    match serde_ignored::deserialize(deserializer, |path| {
                                            warn!("Ignoring unknown field in body: {}", path);
                                            unused_elements.push(path.to_string());
                                    }) {
                                        Ok(param_access_record) => param_access_record,
                                        Err(e) => return Ok(Response::builder()
                                                        .status(StatusCode::BAD_REQUEST)
                                                        .body(Body::from(format!("Couldn't parse body parameter AccessRecord - doesn't match schema: {}", e)))
                                                        .expect("Unable to create Bad Request response for invalid body parameter AccessRecord due to schema")),
                                    }
                                } else {
                                    None
                                };
                                let param_access_record = match param_access_record {
                                    Some(param_access_record) => param_access_record,
                                    None => return Ok(Response::builder()
                                                        .status(StatusCode::BAD_REQUEST)
                                                        .body(Body::from("Missing required body parameter AccessRecord"))
                                                        .expect("Unable to create Bad Request response for missing body parameter AccessRecord")),
                                };

                                let result = api_impl.update_record(
                                            param_record_id,
                                            param_access_record,
                                            param_if_unmodified_since,
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        if !unused_elements.is_empty() {
                                            response.headers_mut().insert(
                                                HeaderName::from_static("warning"),
                                                HeaderValue::from_str(format!("Ignoring unknown fields in body: {:?}", unused_elements).as_str())
                                                    .expect("Unable to create Warning header value"));
                                        }

                                        match result {
                                            Ok(rsp) => match rsp {
                                                UpdateRecordResponse::Success
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(202).expect("Unable to turn 202 into a StatusCode");
                                                },
                                                UpdateRecordResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");
                                                },
                                                UpdateRecordResponse::Forbidden
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(403).expect("Unable to turn 403 into a StatusCode");
                                                },
                                                UpdateRecordResponse::NotFound
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(404).expect("Unable to turn 404 into a StatusCode");
                                                },
                                                UpdateRecordResponse::PreconditionFailed
                                                    {
                                                        last_modified
                                                    }
                                                => {
                                                    if let Some(last_modified) = last_modified {
                                                    let last_modified = match header::IntoHeaderValue(last_modified).try_into() {
                                                        Ok(val) => val,
                                                        Err(e) => {
                                                            return Ok(Response::builder()
                                                                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                                                                    .body(Body::from(format!("An internal server error occurred handling last_modified header - {}", e)))
                                                                    .expect("Unable to create Internal Server Error for invalid response header"))
                                                        }
                                                    };

                                                    response.headers_mut().insert(
                                                        HeaderName::from_static("last-modified"),
                                                        last_modified
                                                    );
                                                    }
                                                    *response.status_mut() = StatusCode::from_u16(412).expect("Unable to turn 412 into a StatusCode");
                                                },
                                                UpdateRecordResponse::TheSizeOfTheRecordIsLargerThanAllowed
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(413).expect("Unable to turn 413 into a StatusCode");
                                                },
                                            },
                                            Err(ApiError::NotImplementedError(_)) => {
                                                *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
                                                *response.body_mut() = Body::from(IMPLEMENTATION_NOT_YET_AVAILABLE_ERROR_STRING);
                                            },
                                            // Application code returned an error. This should not happen, as the implementation should return a valid response.
                                            Err(ApiError::UnknownApiError(error_message)) => {
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from(format!("An internal error occurred {}", error_message));
                                            }
                                        }

                                        Ok(response)
                            },
                            Err(e) => Ok(Response::builder()
                                                .status(StatusCode::BAD_REQUEST)
                                                .body(Body::from(format!("Couldn't read body parameter AccessRecord: {}", e)))
                                                .expect("Unable to create Bad Request response due to unable to read body parameter AccessRecord")),
                        }
            },

            // DelegateAuthentication - POST /v1/identities
            hyper::Method::POST if path.matched(paths::ID_V1_IDENTITIES) => {
                {
                    let authorization = match *(&context as &dyn Has<Option<Authorization>>).get() {
                        Some(ref authorization) => authorization,
                        None => return Ok(Response::builder()
                                                .status(StatusCode::FORBIDDEN)
                                                .body(Body::from("Unauthenticated"))
                                                .expect("Unable to create Authentication Forbidden response")),
                    };
                }

                // Body parameters (note that non-required body parameters will ignore garbage
                // values, rather than causing a 400 response). Produce warning header and logs for
                // any unused fields.
                let result = body.into_raw().await;
                match result {
                            Ok(body) => {
                                let mut unused_elements = Vec::new();
                                let param_identity_request: Option<IdentityRequest> = if !body.is_empty() {
                                    let deserializer = &mut serde_json::Deserializer::from_slice(&body);
                                    match serde_ignored::deserialize(deserializer, |path| {
                                            warn!("Ignoring unknown field in body: {}", path);
                                            unused_elements.push(path.to_string());
                                    }) {
                                        Ok(param_identity_request) => param_identity_request,
                                        Err(e) => return Ok(Response::builder()
                                                        .status(StatusCode::BAD_REQUEST)
                                                        .body(Body::from(format!("Couldn't parse body parameter IdentityRequest - doesn't match schema: {}", e)))
                                                        .expect("Unable to create Bad Request response for invalid body parameter IdentityRequest due to schema")),
                                    }
                                } else {
                                    None
                                };
                                let param_identity_request = match param_identity_request {
                                    Some(param_identity_request) => param_identity_request,
                                    None => return Ok(Response::builder()
                                                        .status(StatusCode::BAD_REQUEST)
                                                        .body(Body::from("Missing required body parameter IdentityRequest"))
                                                        .expect("Unable to create Bad Request response for missing body parameter IdentityRequest")),
                                };

                                let result = api_impl.delegate_authentication(
                                            param_identity_request,
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        if !unused_elements.is_empty() {
                                            response.headers_mut().insert(
                                                HeaderName::from_static("warning"),
                                                HeaderValue::from_str(format!("Ignoring unknown fields in body: {:?}", unused_elements).as_str())
                                                    .expect("Unable to create Warning header value"));
                                        }

                                        match result {
                                            Ok(rsp) => match rsp {
                                                DelegateAuthenticationResponse::Success
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(201).expect("Unable to turn 201 into a StatusCode");
                                                },
                                                DelegateAuthenticationResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");
                                                },
                                                DelegateAuthenticationResponse::Forbidden
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(403).expect("Unable to turn 403 into a StatusCode");
                                                },
                                            },
                                            Err(ApiError::NotImplementedError(_)) => {
                                                *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
                                                *response.body_mut() = Body::from(IMPLEMENTATION_NOT_YET_AVAILABLE_ERROR_STRING);
                                            },
                                            // Application code returned an error. This should not happen, as the implementation should return a valid response.
                                            Err(ApiError::UnknownApiError(error_message)) => {
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from(format!("An internal error occurred {}", error_message));
                                            }
                                        }

                                        Ok(response)
                            },
                            Err(e) => Ok(Response::builder()
                                                .status(StatusCode::BAD_REQUEST)
                                                .body(Body::from(format!("Couldn't read body parameter IdentityRequest: {}", e)))
                                                .expect("Unable to create Bad Request response due to unable to read body parameter IdentityRequest")),
                        }
            },

            // GetAccount - GET /v1/accounts/{accountId}
            hyper::Method::GET if path.matched(paths::ID_V1_ACCOUNTS_ACCOUNTID) => {
                {
                    let authorization = match *(&context as &dyn Has<Option<Authorization>>).get() {
                        Some(ref authorization) => authorization,
                        None => return Ok(Response::builder()
                                                .status(StatusCode::FORBIDDEN)
                                                .body(Body::from("Unauthenticated"))
                                                .expect("Unable to create Authentication Forbidden response")),
                    };
                }

                // Path parameters
                let path: &str = uri.path();
                let path_params =
                    paths::REGEX_V1_ACCOUNTS_ACCOUNTID
                    .captures(path)
                    .unwrap_or_else(||
                        panic!("Path {} matched RE V1_ACCOUNTS_ACCOUNTID in set but failed match against \"{}\"", path, paths::REGEX_V1_ACCOUNTS_ACCOUNTID.as_str())
                    );

                let param_account_id = match percent_encoding::percent_decode(path_params["accountId"].as_bytes()).decode_utf8() {
                    Ok(param_account_id) => match param_account_id.parse::<String>() {
                        Ok(param_account_id) => param_account_id,
                        Err(e) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't parse path parameter accountId: {}", e)))
                                        .expect("Unable to create Bad Request response for invalid path parameter")),
                    },
                    Err(_) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't percent-decode path parameter as UTF-8: {}", &path_params["accountId"])))
                                        .expect("Unable to create Bad Request response for invalid percent decode"))
                };

                                let result = api_impl.get_account(
                                            param_account_id,
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        match result {
                                            Ok(rsp) => match rsp {
                                                GetAccountResponse::Success
                                                    (body)
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(200).expect("Unable to turn 200 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_str("application/links+json")
                                                            .expect("Unable to create Content-Type header for GET_ACCOUNT_SUCCESS"));
                                                    let body = body;
                                                    *response.body_mut() = Body::from(body);
                                                },
                                                GetAccountResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");
                                                },
                                                GetAccountResponse::NotFound
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(404).expect("Unable to turn 404 into a StatusCode");
                                                },
                                            },
                                            Err(ApiError::NotImplementedError(_)) => {
                                                *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
                                                *response.body_mut() = Body::from(IMPLEMENTATION_NOT_YET_AVAILABLE_ERROR_STRING);
                                            },
                                            // Application code returned an error. This should not happen, as the implementation should return a valid response.
                                            Err(ApiError::UnknownApiError(error_message)) => {
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from(format!("An internal error occurred {}", error_message));
                                            }
                                        }

                                        Ok(response)
            },

            // GetAccountIdentities - GET /v1/identities
            hyper::Method::GET if path.matched(paths::ID_V1_IDENTITIES) => {
                {
                    let authorization = match *(&context as &dyn Has<Option<Authorization>>).get() {
                        Some(ref authorization) => authorization,
                        None => return Ok(Response::builder()
                                                .status(StatusCode::FORBIDDEN)
                                                .body(Body::from("Unauthenticated"))
                                                .expect("Unable to create Authentication Forbidden response")),
                    };
                }

                                let result = api_impl.get_account_identities(
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        match result {
                                            Ok(rsp) => match rsp {
                                                GetAccountIdentitiesResponse::Success
                                                    (body)
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(200).expect("Unable to turn 200 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_str("application/links+json")
                                                            .expect("Unable to create Content-Type header for GET_ACCOUNT_IDENTITIES_SUCCESS"));
                                                    let body = body;
                                                    *response.body_mut() = Body::from(body);
                                                },
                                                GetAccountIdentitiesResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");
                                                },
                                                GetAccountIdentitiesResponse::NotFound
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(403).expect("Unable to turn 403 into a StatusCode");
                                                },
                                            },
                                            Err(ApiError::NotImplementedError(_)) => {
                                                *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
                                                *response.body_mut() = Body::from(IMPLEMENTATION_NOT_YET_AVAILABLE_ERROR_STRING);
                                            },
                                            // Application code returned an error. This should not happen, as the implementation should return a valid response.
                                            Err(ApiError::UnknownApiError(error_message)) => {
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from(format!("An internal error occurred {}", error_message));
                                            }
                                        }

                                        Ok(response)
            },

            // GetAccounts - GET /v1/accounts
            hyper::Method::GET if path.matched(paths::ID_V1_ACCOUNTS) => {
                {
                    let authorization = match *(&context as &dyn Has<Option<Authorization>>).get() {
                        Some(ref authorization) => authorization,
                        None => return Ok(Response::builder()
                                                .status(StatusCode::FORBIDDEN)
                                                .body(Body::from("Unauthenticated"))
                                                .expect("Unable to create Authentication Forbidden response")),
                    };
                }

                // Query parameters (note that non-required or collection query parameters will ignore garbage values, rather than causing a 400 response)
                let query_params = form_urlencoded::parse(uri.query().unwrap_or_default().as_bytes()).collect::<Vec<_>>();
                let param_earliest_cache_time = query_params.iter().filter(|e| e.0 == "earliestCacheTime").map(|e| e.1.clone())
                    .next();
                let param_earliest_cache_time = match param_earliest_cache_time {
                    Some(param_earliest_cache_time) => {
                        let param_earliest_cache_time =
                            <chrono::DateTime::<chrono::Utc> as std::str::FromStr>::from_str
                                (&param_earliest_cache_time);
                        match param_earliest_cache_time {
                            Ok(param_earliest_cache_time) => Some(param_earliest_cache_time),
                            Err(e) => return Ok(Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body(Body::from(format!("Couldn't parse query parameter earliestCacheTime - doesn't match schema: {}", e)))
                                .expect("Unable to create Bad Request response for invalid query parameter earliestCacheTime")),
                        }
                    },
                    None => None,
                };

                                let result = api_impl.get_accounts(
                                            param_earliest_cache_time,
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        match result {
                                            Ok(rsp) => match rsp {
                                                GetAccountsResponse::Success
                                                    (body)
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(200).expect("Unable to turn 200 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_str("application/links+json")
                                                            .expect("Unable to create Content-Type header for GET_ACCOUNTS_SUCCESS"));
                                                    let body = body;
                                                    *response.body_mut() = Body::from(body);
                                                },
                                                GetAccountsResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");
                                                },
                                            },
                                            Err(ApiError::NotImplementedError(_)) => {
                                                *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
                                                *response.body_mut() = Body::from(IMPLEMENTATION_NOT_YET_AVAILABLE_ERROR_STRING);
                                            },
                                            // Application code returned an error. This should not happen, as the implementation should return a valid response.
                                            Err(ApiError::UnknownApiError(error_message)) => {
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from(format!("An internal error occurred {}", error_message));
                                            }
                                        }

                                        Ok(response)
            },

            // DelegateUserLogin - POST /v1/applications/{applicationId}/users/{userId}/delegation
            hyper::Method::POST if path.matched(paths::ID_V1_APPLICATIONS_APPLICATIONID_USERS_USERID_DELEGATION) => {
                {
                    let authorization = match *(&context as &dyn Has<Option<Authorization>>).get() {
                        Some(ref authorization) => authorization,
                        None => return Ok(Response::builder()
                                                .status(StatusCode::FORBIDDEN)
                                                .body(Body::from("Unauthenticated"))
                                                .expect("Unable to create Authentication Forbidden response")),
                    };
                }

                // Path parameters
                let path: &str = uri.path();
                let path_params =
                    paths::REGEX_V1_APPLICATIONS_APPLICATIONID_USERS_USERID_DELEGATION
                    .captures(path)
                    .unwrap_or_else(||
                        panic!("Path {} matched RE V1_APPLICATIONS_APPLICATIONID_USERS_USERID_DELEGATION in set but failed match against \"{}\"", path, paths::REGEX_V1_APPLICATIONS_APPLICATIONID_USERS_USERID_DELEGATION.as_str())
                    );

                let param_application_id = match percent_encoding::percent_decode(path_params["applicationId"].as_bytes()).decode_utf8() {
                    Ok(param_application_id) => match param_application_id.parse::<String>() {
                        Ok(param_application_id) => param_application_id,
                        Err(e) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't parse path parameter applicationId: {}", e)))
                                        .expect("Unable to create Bad Request response for invalid path parameter")),
                    },
                    Err(_) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't percent-decode path parameter as UTF-8: {}", &path_params["applicationId"])))
                                        .expect("Unable to create Bad Request response for invalid percent decode"))
                };

                let param_user_id = match percent_encoding::percent_decode(path_params["userId"].as_bytes()).decode_utf8() {
                    Ok(param_user_id) => match param_user_id.parse::<String>() {
                        Ok(param_user_id) => param_user_id,
                        Err(e) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't parse path parameter userId: {}", e)))
                                        .expect("Unable to create Bad Request response for invalid path parameter")),
                    },
                    Err(_) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't percent-decode path parameter as UTF-8: {}", &path_params["userId"])))
                                        .expect("Unable to create Bad Request response for invalid percent decode"))
                };

                                let result = api_impl.delegate_user_login(
                                            param_application_id,
                                            param_user_id,
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        match result {
                                            Ok(rsp) => match rsp {
                                                DelegateUserLoginResponse::Success
                                                    (body)
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(200).expect("Unable to turn 200 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_str("application/links+json")
                                                            .expect("Unable to create Content-Type header for DELEGATE_USER_LOGIN_SUCCESS"));
                                                    let body = body;
                                                    *response.body_mut() = Body::from(body);
                                                },
                                                DelegateUserLoginResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");
                                                },
                                                DelegateUserLoginResponse::Forbidden
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(403).expect("Unable to turn 403 into a StatusCode");
                                                },
                                                DelegateUserLoginResponse::NotFound
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(404).expect("Unable to turn 404 into a StatusCode");
                                                },
                                            },
                                            Err(ApiError::NotImplementedError(_)) => {
                                                *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
                                                *response.body_mut() = Body::from(IMPLEMENTATION_NOT_YET_AVAILABLE_ERROR_STRING);
                                            },
                                            // Application code returned an error. This should not happen, as the implementation should return a valid response.
                                            Err(ApiError::UnknownApiError(error_message)) => {
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from(format!("An internal error occurred {}", error_message));
                                            }
                                        }

                                        Ok(response)
            },

            // CreateConnection - POST /v1/connections
            hyper::Method::POST if path.matched(paths::ID_V1_CONNECTIONS) => {
                {
                    let authorization = match *(&context as &dyn Has<Option<Authorization>>).get() {
                        Some(ref authorization) => authorization,
                        None => return Ok(Response::builder()
                                                .status(StatusCode::FORBIDDEN)
                                                .body(Body::from("Unauthenticated"))
                                                .expect("Unable to create Authentication Forbidden response")),
                    };
                }

                // Body parameters (note that non-required body parameters will ignore garbage
                // values, rather than causing a 400 response). Produce warning header and logs for
                // any unused fields.
                let result = body.into_raw().await;
                match result {
                            Ok(body) => {
                                let mut unused_elements = Vec::new();
                                let param_connection: Option<Connection> = if !body.is_empty() {
                                    let deserializer = &mut serde_json::Deserializer::from_slice(&body);
                                    match serde_ignored::deserialize(deserializer, |path| {
                                            warn!("Ignoring unknown field in body: {}", path);
                                            unused_elements.push(path.to_string());
                                    }) {
                                        Ok(param_connection) => param_connection,
                                        Err(e) => return Ok(Response::builder()
                                                        .status(StatusCode::BAD_REQUEST)
                                                        .body(Body::from(format!("Couldn't parse body parameter Connection - doesn't match schema: {}", e)))
                                                        .expect("Unable to create Bad Request response for invalid body parameter Connection due to schema")),
                                    }
                                } else {
                                    None
                                };
                                let param_connection = match param_connection {
                                    Some(param_connection) => param_connection,
                                    None => return Ok(Response::builder()
                                                        .status(StatusCode::BAD_REQUEST)
                                                        .body(Body::from("Missing required body parameter Connection"))
                                                        .expect("Unable to create Bad Request response for missing body parameter Connection")),
                                };

                                let result = api_impl.create_connection(
                                            param_connection,
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        if !unused_elements.is_empty() {
                                            response.headers_mut().insert(
                                                HeaderName::from_static("warning"),
                                                HeaderValue::from_str(format!("Ignoring unknown fields in body: {:?}", unused_elements).as_str())
                                                    .expect("Unable to create Warning header value"));
                                        }

                                        match result {
                                            Ok(rsp) => match rsp {
                                                CreateConnectionResponse::Success
                                                    (body)
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(201).expect("Unable to turn 201 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_str("application/links+json")
                                                            .expect("Unable to create Content-Type header for CREATE_CONNECTION_SUCCESS"));
                                                    let body = body;
                                                    *response.body_mut() = Body::from(body);
                                                },
                                                CreateConnectionResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");
                                                },
                                                CreateConnectionResponse::Forbidden
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(403).expect("Unable to turn 403 into a StatusCode");
                                                },
                                            },
                                            Err(ApiError::NotImplementedError(_)) => {
                                                *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
                                                *response.body_mut() = Body::from(IMPLEMENTATION_NOT_YET_AVAILABLE_ERROR_STRING);
                                            },
                                            // Application code returned an error. This should not happen, as the implementation should return a valid response.
                                            Err(ApiError::UnknownApiError(error_message)) => {
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from(format!("An internal error occurred {}", error_message));
                                            }
                                        }

                                        Ok(response)
                            },
                            Err(e) => Ok(Response::builder()
                                                .status(StatusCode::BAD_REQUEST)
                                                .body(Body::from(format!("Couldn't read body parameter Connection: {}", e)))
                                                .expect("Unable to create Bad Request response due to unable to read body parameter Connection")),
                        }
            },

            // DeleteConnection - DELETE /v1/connections/{connectionId}
            hyper::Method::DELETE if path.matched(paths::ID_V1_CONNECTIONS_CONNECTIONID) => {
                {
                    let authorization = match *(&context as &dyn Has<Option<Authorization>>).get() {
                        Some(ref authorization) => authorization,
                        None => return Ok(Response::builder()
                                                .status(StatusCode::FORBIDDEN)
                                                .body(Body::from("Unauthenticated"))
                                                .expect("Unable to create Authentication Forbidden response")),
                    };
                }

                // Path parameters
                let path: &str = uri.path();
                let path_params =
                    paths::REGEX_V1_CONNECTIONS_CONNECTIONID
                    .captures(path)
                    .unwrap_or_else(||
                        panic!("Path {} matched RE V1_CONNECTIONS_CONNECTIONID in set but failed match against \"{}\"", path, paths::REGEX_V1_CONNECTIONS_CONNECTIONID.as_str())
                    );

                let param_connection_id = match percent_encoding::percent_decode(path_params["connectionId"].as_bytes()).decode_utf8() {
                    Ok(param_connection_id) => match param_connection_id.parse::<String>() {
                        Ok(param_connection_id) => param_connection_id,
                        Err(e) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't parse path parameter connectionId: {}", e)))
                                        .expect("Unable to create Bad Request response for invalid path parameter")),
                    },
                    Err(_) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't percent-decode path parameter as UTF-8: {}", &path_params["connectionId"])))
                                        .expect("Unable to create Bad Request response for invalid percent decode"))
                };

                                let result = api_impl.delete_connection(
                                            param_connection_id,
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        match result {
                                            Ok(rsp) => match rsp {
                                                DeleteConnectionResponse::Success
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(204).expect("Unable to turn 204 into a StatusCode");
                                                },
                                                DeleteConnectionResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");
                                                },
                                                DeleteConnectionResponse::Forbidden
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(403).expect("Unable to turn 403 into a StatusCode");
                                                },
                                                DeleteConnectionResponse::NotFound
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(404).expect("Unable to turn 404 into a StatusCode");
                                                },
                                            },
                                            Err(ApiError::NotImplementedError(_)) => {
                                                *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
                                                *response.body_mut() = Body::from(IMPLEMENTATION_NOT_YET_AVAILABLE_ERROR_STRING);
                                            },
                                            // Application code returned an error. This should not happen, as the implementation should return a valid response.
                                            Err(ApiError::UnknownApiError(error_message)) => {
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from(format!("An internal error occurred {}", error_message));
                                            }
                                        }

                                        Ok(response)
            },

            // GetConnection - GET /v1/connections/{connectionId}
            hyper::Method::GET if path.matched(paths::ID_V1_CONNECTIONS_CONNECTIONID) => {
                {
                    let authorization = match *(&context as &dyn Has<Option<Authorization>>).get() {
                        Some(ref authorization) => authorization,
                        None => return Ok(Response::builder()
                                                .status(StatusCode::FORBIDDEN)
                                                .body(Body::from("Unauthenticated"))
                                                .expect("Unable to create Authentication Forbidden response")),
                    };
                }

                // Path parameters
                let path: &str = uri.path();
                let path_params =
                    paths::REGEX_V1_CONNECTIONS_CONNECTIONID
                    .captures(path)
                    .unwrap_or_else(||
                        panic!("Path {} matched RE V1_CONNECTIONS_CONNECTIONID in set but failed match against \"{}\"", path, paths::REGEX_V1_CONNECTIONS_CONNECTIONID.as_str())
                    );

                let param_connection_id = match percent_encoding::percent_decode(path_params["connectionId"].as_bytes()).decode_utf8() {
                    Ok(param_connection_id) => match param_connection_id.parse::<String>() {
                        Ok(param_connection_id) => param_connection_id,
                        Err(e) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't parse path parameter connectionId: {}", e)))
                                        .expect("Unable to create Bad Request response for invalid path parameter")),
                    },
                    Err(_) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't percent-decode path parameter as UTF-8: {}", &path_params["connectionId"])))
                                        .expect("Unable to create Bad Request response for invalid percent decode"))
                };

                                let result = api_impl.get_connection(
                                            param_connection_id,
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        match result {
                                            Ok(rsp) => match rsp {
                                                GetConnectionResponse::Success
                                                    (body)
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(200).expect("Unable to turn 200 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_str("application/links+json")
                                                            .expect("Unable to create Content-Type header for GET_CONNECTION_SUCCESS"));
                                                    let body = body;
                                                    *response.body_mut() = Body::from(body);
                                                },
                                                GetConnectionResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");
                                                },
                                                GetConnectionResponse::Forbidden
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(403).expect("Unable to turn 403 into a StatusCode");
                                                },
                                                GetConnectionResponse::NotFound
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(404).expect("Unable to turn 404 into a StatusCode");
                                                },
                                            },
                                            Err(ApiError::NotImplementedError(_)) => {
                                                *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
                                                *response.body_mut() = Body::from(IMPLEMENTATION_NOT_YET_AVAILABLE_ERROR_STRING);
                                            },
                                            // Application code returned an error. This should not happen, as the implementation should return a valid response.
                                            Err(ApiError::UnknownApiError(error_message)) => {
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from(format!("An internal error occurred {}", error_message));
                                            }
                                        }

                                        Ok(response)
            },

            // GetConnectionCredentials - GET /v1/connections/{connectionId}/users/{userId}/credentials
            hyper::Method::GET if path.matched(paths::ID_V1_CONNECTIONS_CONNECTIONID_USERS_USERID_CREDENTIALS) => {
                {
                    let authorization = match *(&context as &dyn Has<Option<Authorization>>).get() {
                        Some(ref authorization) => authorization,
                        None => return Ok(Response::builder()
                                                .status(StatusCode::FORBIDDEN)
                                                .body(Body::from("Unauthenticated"))
                                                .expect("Unable to create Authentication Forbidden response")),
                    };
                }

                // Path parameters
                let path: &str = uri.path();
                let path_params =
                    paths::REGEX_V1_CONNECTIONS_CONNECTIONID_USERS_USERID_CREDENTIALS
                    .captures(path)
                    .unwrap_or_else(||
                        panic!("Path {} matched RE V1_CONNECTIONS_CONNECTIONID_USERS_USERID_CREDENTIALS in set but failed match against \"{}\"", path, paths::REGEX_V1_CONNECTIONS_CONNECTIONID_USERS_USERID_CREDENTIALS.as_str())
                    );

                let param_connection_id = match percent_encoding::percent_decode(path_params["connectionId"].as_bytes()).decode_utf8() {
                    Ok(param_connection_id) => match param_connection_id.parse::<String>() {
                        Ok(param_connection_id) => param_connection_id,
                        Err(e) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't parse path parameter connectionId: {}", e)))
                                        .expect("Unable to create Bad Request response for invalid path parameter")),
                    },
                    Err(_) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't percent-decode path parameter as UTF-8: {}", &path_params["connectionId"])))
                                        .expect("Unable to create Bad Request response for invalid percent decode"))
                };

                let param_user_id = match percent_encoding::percent_decode(path_params["userId"].as_bytes()).decode_utf8() {
                    Ok(param_user_id) => match param_user_id.parse::<String>() {
                        Ok(param_user_id) => param_user_id,
                        Err(e) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't parse path parameter userId: {}", e)))
                                        .expect("Unable to create Bad Request response for invalid path parameter")),
                    },
                    Err(_) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't percent-decode path parameter as UTF-8: {}", &path_params["userId"])))
                                        .expect("Unable to create Bad Request response for invalid percent decode"))
                };

                                let result = api_impl.get_connection_credentials(
                                            param_connection_id,
                                            param_user_id,
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        match result {
                                            Ok(rsp) => match rsp {
                                                GetConnectionCredentialsResponse::Success
                                                    (body)
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(200).expect("Unable to turn 200 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_str("application/links+json")
                                                            .expect("Unable to create Content-Type header for GET_CONNECTION_CREDENTIALS_SUCCESS"));
                                                    let body = body;
                                                    *response.body_mut() = Body::from(body);
                                                },
                                                GetConnectionCredentialsResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");
                                                },
                                                GetConnectionCredentialsResponse::Forbidden
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(403).expect("Unable to turn 403 into a StatusCode");
                                                },
                                                GetConnectionCredentialsResponse::NotFound
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(404).expect("Unable to turn 404 into a StatusCode");
                                                },
                                            },
                                            Err(ApiError::NotImplementedError(_)) => {
                                                *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
                                                *response.body_mut() = Body::from(IMPLEMENTATION_NOT_YET_AVAILABLE_ERROR_STRING);
                                            },
                                            // Application code returned an error. This should not happen, as the implementation should return a valid response.
                                            Err(ApiError::UnknownApiError(error_message)) => {
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from(format!("An internal error occurred {}", error_message));
                                            }
                                        }

                                        Ok(response)
            },

            // GetConnections - GET /v1/connections
            hyper::Method::GET if path.matched(paths::ID_V1_CONNECTIONS) => {
                {
                    let authorization = match *(&context as &dyn Has<Option<Authorization>>).get() {
                        Some(ref authorization) => authorization,
                        None => return Ok(Response::builder()
                                                .status(StatusCode::FORBIDDEN)
                                                .body(Body::from("Unauthenticated"))
                                                .expect("Unable to create Authentication Forbidden response")),
                    };
                }

                                let result = api_impl.get_connections(
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        match result {
                                            Ok(rsp) => match rsp {
                                                GetConnectionsResponse::Success
                                                    (body)
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(200).expect("Unable to turn 200 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_str("application/links+json")
                                                            .expect("Unable to create Content-Type header for GET_CONNECTIONS_SUCCESS"));
                                                    let body = body;
                                                    *response.body_mut() = Body::from(body);
                                                },
                                                GetConnectionsResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");
                                                },
                                                GetConnectionsResponse::Forbidden
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(403).expect("Unable to turn 403 into a StatusCode");
                                                },
                                            },
                                            Err(ApiError::NotImplementedError(_)) => {
                                                *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
                                                *response.body_mut() = Body::from(IMPLEMENTATION_NOT_YET_AVAILABLE_ERROR_STRING);
                                            },
                                            // Application code returned an error. This should not happen, as the implementation should return a valid response.
                                            Err(ApiError::UnknownApiError(error_message)) => {
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from(format!("An internal error occurred {}", error_message));
                                            }
                                        }

                                        Ok(response)
            },

            // UpdateConnection - PUT /v1/connections/{connectionId}
            hyper::Method::PUT if path.matched(paths::ID_V1_CONNECTIONS_CONNECTIONID) => {
                {
                    let authorization = match *(&context as &dyn Has<Option<Authorization>>).get() {
                        Some(ref authorization) => authorization,
                        None => return Ok(Response::builder()
                                                .status(StatusCode::FORBIDDEN)
                                                .body(Body::from("Unauthenticated"))
                                                .expect("Unable to create Authentication Forbidden response")),
                    };
                }

                // Path parameters
                let path: &str = uri.path();
                let path_params =
                    paths::REGEX_V1_CONNECTIONS_CONNECTIONID
                    .captures(path)
                    .unwrap_or_else(||
                        panic!("Path {} matched RE V1_CONNECTIONS_CONNECTIONID in set but failed match against \"{}\"", path, paths::REGEX_V1_CONNECTIONS_CONNECTIONID.as_str())
                    );

                let param_connection_id = match percent_encoding::percent_decode(path_params["connectionId"].as_bytes()).decode_utf8() {
                    Ok(param_connection_id) => match param_connection_id.parse::<String>() {
                        Ok(param_connection_id) => param_connection_id,
                        Err(e) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't parse path parameter connectionId: {}", e)))
                                        .expect("Unable to create Bad Request response for invalid path parameter")),
                    },
                    Err(_) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't percent-decode path parameter as UTF-8: {}", &path_params["connectionId"])))
                                        .expect("Unable to create Bad Request response for invalid percent decode"))
                };

                // Body parameters (note that non-required body parameters will ignore garbage
                // values, rather than causing a 400 response). Produce warning header and logs for
                // any unused fields.
                let result = body.into_raw().await;
                match result {
                            Ok(body) => {
                                let mut unused_elements = Vec::new();
                                let param_connection: Option<Connection> = if !body.is_empty() {
                                    let deserializer = &mut serde_json::Deserializer::from_slice(&body);
                                    match serde_ignored::deserialize(deserializer, |path| {
                                            warn!("Ignoring unknown field in body: {}", path);
                                            unused_elements.push(path.to_string());
                                    }) {
                                        Ok(param_connection) => param_connection,
                                        Err(e) => return Ok(Response::builder()
                                                        .status(StatusCode::BAD_REQUEST)
                                                        .body(Body::from(format!("Couldn't parse body parameter Connection - doesn't match schema: {}", e)))
                                                        .expect("Unable to create Bad Request response for invalid body parameter Connection due to schema")),
                                    }
                                } else {
                                    None
                                };
                                let param_connection = match param_connection {
                                    Some(param_connection) => param_connection,
                                    None => return Ok(Response::builder()
                                                        .status(StatusCode::BAD_REQUEST)
                                                        .body(Body::from("Missing required body parameter Connection"))
                                                        .expect("Unable to create Bad Request response for missing body parameter Connection")),
                                };

                                let result = api_impl.update_connection(
                                            param_connection_id,
                                            param_connection,
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        if !unused_elements.is_empty() {
                                            response.headers_mut().insert(
                                                HeaderName::from_static("warning"),
                                                HeaderValue::from_str(format!("Ignoring unknown fields in body: {:?}", unused_elements).as_str())
                                                    .expect("Unable to create Warning header value"));
                                        }

                                        match result {
                                            Ok(rsp) => match rsp {
                                                UpdateConnectionResponse::Success
                                                    (body)
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(200).expect("Unable to turn 200 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_str("application/links+json")
                                                            .expect("Unable to create Content-Type header for UPDATE_CONNECTION_SUCCESS"));
                                                    let body = body;
                                                    *response.body_mut() = Body::from(body);
                                                },
                                                UpdateConnectionResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");
                                                },
                                                UpdateConnectionResponse::Forbidden
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(403).expect("Unable to turn 403 into a StatusCode");
                                                },
                                                UpdateConnectionResponse::NotFound
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(404).expect("Unable to turn 404 into a StatusCode");
                                                },
                                            },
                                            Err(ApiError::NotImplementedError(_)) => {
                                                *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
                                                *response.body_mut() = Body::from(IMPLEMENTATION_NOT_YET_AVAILABLE_ERROR_STRING);
                                            },
                                            // Application code returned an error. This should not happen, as the implementation should return a valid response.
                                            Err(ApiError::UnknownApiError(error_message)) => {
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from(format!("An internal error occurred {}", error_message));
                                            }
                                        }

                                        Ok(response)
                            },
                            Err(e) => Ok(Response::builder()
                                                .status(StatusCode::BAD_REQUEST)
                                                .body(Body::from(format!("Couldn't read body parameter Connection: {}", e)))
                                                .expect("Unable to create Bad Request response due to unable to read body parameter Connection")),
                        }
            },

            // CreateExtension - POST /v1/extensions
            hyper::Method::POST if path.matched(paths::ID_V1_EXTENSIONS) => {
                {
                    let authorization = match *(&context as &dyn Has<Option<Authorization>>).get() {
                        Some(ref authorization) => authorization,
                        None => return Ok(Response::builder()
                                                .status(StatusCode::FORBIDDEN)
                                                .body(Body::from("Unauthenticated"))
                                                .expect("Unable to create Authentication Forbidden response")),
                    };
                }

                // Body parameters (note that non-required body parameters will ignore garbage
                // values, rather than causing a 400 response). Produce warning header and logs for
                // any unused fields.
                let result = body.into_raw().await;
                match result {
                            Ok(body) => {
                                let mut unused_elements = Vec::new();
                                let param_extension: Option<Extension> = if !body.is_empty() {
                                    let deserializer = &mut serde_json::Deserializer::from_slice(&body);
                                    match serde_ignored::deserialize(deserializer, |path| {
                                            warn!("Ignoring unknown field in body: {}", path);
                                            unused_elements.push(path.to_string());
                                    }) {
                                        Ok(param_extension) => param_extension,
                                        Err(e) => return Ok(Response::builder()
                                                        .status(StatusCode::BAD_REQUEST)
                                                        .body(Body::from(format!("Couldn't parse body parameter Extension - doesn't match schema: {}", e)))
                                                        .expect("Unable to create Bad Request response for invalid body parameter Extension due to schema")),
                                    }
                                } else {
                                    None
                                };
                                let param_extension = match param_extension {
                                    Some(param_extension) => param_extension,
                                    None => return Ok(Response::builder()
                                                        .status(StatusCode::BAD_REQUEST)
                                                        .body(Body::from("Missing required body parameter Extension"))
                                                        .expect("Unable to create Bad Request response for missing body parameter Extension")),
                                };

                                let result = api_impl.create_extension(
                                            param_extension,
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        if !unused_elements.is_empty() {
                                            response.headers_mut().insert(
                                                HeaderName::from_static("warning"),
                                                HeaderValue::from_str(format!("Ignoring unknown fields in body: {:?}", unused_elements).as_str())
                                                    .expect("Unable to create Warning header value"));
                                        }

                                        match result {
                                            Ok(rsp) => match rsp {
                                                CreateExtensionResponse::Success
                                                    (body)
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(201).expect("Unable to turn 201 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_str("application/links+json")
                                                            .expect("Unable to create Content-Type header for CREATE_EXTENSION_SUCCESS"));
                                                    let body = body;
                                                    *response.body_mut() = Body::from(body);
                                                },
                                                CreateExtensionResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");
                                                },
                                                CreateExtensionResponse::Forbidden
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(403).expect("Unable to turn 403 into a StatusCode");
                                                },
                                            },
                                            Err(ApiError::NotImplementedError(_)) => {
                                                *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
                                                *response.body_mut() = Body::from(IMPLEMENTATION_NOT_YET_AVAILABLE_ERROR_STRING);
                                            },
                                            // Application code returned an error. This should not happen, as the implementation should return a valid response.
                                            Err(ApiError::UnknownApiError(error_message)) => {
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from(format!("An internal error occurred {}", error_message));
                                            }
                                        }

                                        Ok(response)
                            },
                            Err(e) => Ok(Response::builder()
                                                .status(StatusCode::BAD_REQUEST)
                                                .body(Body::from(format!("Couldn't read body parameter Extension: {}", e)))
                                                .expect("Unable to create Bad Request response due to unable to read body parameter Extension")),
                        }
            },

            // DeleteExtension - DELETE /v1/extensions/{extensionId}
            hyper::Method::DELETE if path.matched(paths::ID_V1_EXTENSIONS_EXTENSIONID) => {
                {
                    let authorization = match *(&context as &dyn Has<Option<Authorization>>).get() {
                        Some(ref authorization) => authorization,
                        None => return Ok(Response::builder()
                                                .status(StatusCode::FORBIDDEN)
                                                .body(Body::from("Unauthenticated"))
                                                .expect("Unable to create Authentication Forbidden response")),
                    };
                }

                // Path parameters
                let path: &str = uri.path();
                let path_params =
                    paths::REGEX_V1_EXTENSIONS_EXTENSIONID
                    .captures(path)
                    .unwrap_or_else(||
                        panic!("Path {} matched RE V1_EXTENSIONS_EXTENSIONID in set but failed match against \"{}\"", path, paths::REGEX_V1_EXTENSIONS_EXTENSIONID.as_str())
                    );

                let param_extension_id = match percent_encoding::percent_decode(path_params["extensionId"].as_bytes()).decode_utf8() {
                    Ok(param_extension_id) => match param_extension_id.parse::<String>() {
                        Ok(param_extension_id) => param_extension_id,
                        Err(e) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't parse path parameter extensionId: {}", e)))
                                        .expect("Unable to create Bad Request response for invalid path parameter")),
                    },
                    Err(_) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't percent-decode path parameter as UTF-8: {}", &path_params["extensionId"])))
                                        .expect("Unable to create Bad Request response for invalid percent decode"))
                };

                                let result = api_impl.delete_extension(
                                            param_extension_id,
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        match result {
                                            Ok(rsp) => match rsp {
                                                DeleteExtensionResponse::Success
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(204).expect("Unable to turn 204 into a StatusCode");
                                                },
                                                DeleteExtensionResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");
                                                },
                                                DeleteExtensionResponse::Forbidden
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(403).expect("Unable to turn 403 into a StatusCode");
                                                },
                                                DeleteExtensionResponse::NotFound
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(404).expect("Unable to turn 404 into a StatusCode");
                                                },
                                            },
                                            Err(ApiError::NotImplementedError(_)) => {
                                                *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
                                                *response.body_mut() = Body::from(IMPLEMENTATION_NOT_YET_AVAILABLE_ERROR_STRING);
                                            },
                                            // Application code returned an error. This should not happen, as the implementation should return a valid response.
                                            Err(ApiError::UnknownApiError(error_message)) => {
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from(format!("An internal error occurred {}", error_message));
                                            }
                                        }

                                        Ok(response)
            },

            // GetExtension - GET /v1/extensions/{extensionId}
            hyper::Method::GET if path.matched(paths::ID_V1_EXTENSIONS_EXTENSIONID) => {
                {
                    let authorization = match *(&context as &dyn Has<Option<Authorization>>).get() {
                        Some(ref authorization) => authorization,
                        None => return Ok(Response::builder()
                                                .status(StatusCode::FORBIDDEN)
                                                .body(Body::from("Unauthenticated"))
                                                .expect("Unable to create Authentication Forbidden response")),
                    };
                }

                // Path parameters
                let path: &str = uri.path();
                let path_params =
                    paths::REGEX_V1_EXTENSIONS_EXTENSIONID
                    .captures(path)
                    .unwrap_or_else(||
                        panic!("Path {} matched RE V1_EXTENSIONS_EXTENSIONID in set but failed match against \"{}\"", path, paths::REGEX_V1_EXTENSIONS_EXTENSIONID.as_str())
                    );

                let param_extension_id = match percent_encoding::percent_decode(path_params["extensionId"].as_bytes()).decode_utf8() {
                    Ok(param_extension_id) => match param_extension_id.parse::<String>() {
                        Ok(param_extension_id) => param_extension_id,
                        Err(e) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't parse path parameter extensionId: {}", e)))
                                        .expect("Unable to create Bad Request response for invalid path parameter")),
                    },
                    Err(_) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't percent-decode path parameter as UTF-8: {}", &path_params["extensionId"])))
                                        .expect("Unable to create Bad Request response for invalid percent decode"))
                };

                                let result = api_impl.get_extension(
                                            param_extension_id,
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        match result {
                                            Ok(rsp) => match rsp {
                                                GetExtensionResponse::Success
                                                    (body)
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(200).expect("Unable to turn 200 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_str("application/links+json")
                                                            .expect("Unable to create Content-Type header for GET_EXTENSION_SUCCESS"));
                                                    let body = body;
                                                    *response.body_mut() = Body::from(body);
                                                },
                                                GetExtensionResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");
                                                },
                                                GetExtensionResponse::Forbidden
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(403).expect("Unable to turn 403 into a StatusCode");
                                                },
                                                GetExtensionResponse::NotFound
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(404).expect("Unable to turn 404 into a StatusCode");
                                                },
                                            },
                                            Err(ApiError::NotImplementedError(_)) => {
                                                *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
                                                *response.body_mut() = Body::from(IMPLEMENTATION_NOT_YET_AVAILABLE_ERROR_STRING);
                                            },
                                            // Application code returned an error. This should not happen, as the implementation should return a valid response.
                                            Err(ApiError::UnknownApiError(error_message)) => {
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from(format!("An internal error occurred {}", error_message));
                                            }
                                        }

                                        Ok(response)
            },

            // GetExtensions - GET /v1/extensions
            hyper::Method::GET if path.matched(paths::ID_V1_EXTENSIONS) => {
                {
                    let authorization = match *(&context as &dyn Has<Option<Authorization>>).get() {
                        Some(ref authorization) => authorization,
                        None => return Ok(Response::builder()
                                                .status(StatusCode::FORBIDDEN)
                                                .body(Body::from("Unauthenticated"))
                                                .expect("Unable to create Authentication Forbidden response")),
                    };
                }

                                let result = api_impl.get_extensions(
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        match result {
                                            Ok(rsp) => match rsp {
                                                GetExtensionsResponse::Success
                                                    (body)
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(200).expect("Unable to turn 200 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_str("application/links+json")
                                                            .expect("Unable to create Content-Type header for GET_EXTENSIONS_SUCCESS"));
                                                    let body = body;
                                                    *response.body_mut() = Body::from(body);
                                                },
                                                GetExtensionsResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");
                                                },
                                                GetExtensionsResponse::Forbidden
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(403).expect("Unable to turn 403 into a StatusCode");
                                                },
                                            },
                                            Err(ApiError::NotImplementedError(_)) => {
                                                *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
                                                *response.body_mut() = Body::from(IMPLEMENTATION_NOT_YET_AVAILABLE_ERROR_STRING);
                                            },
                                            // Application code returned an error. This should not happen, as the implementation should return a valid response.
                                            Err(ApiError::UnknownApiError(error_message)) => {
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from(format!("An internal error occurred {}", error_message));
                                            }
                                        }

                                        Ok(response)
            },

            // Login - GET /
            hyper::Method::GET if path.matched(paths::ID_) => {
                // Query parameters (note that non-required or collection query parameters will ignore garbage values, rather than causing a 400 response)
                let query_params = form_urlencoded::parse(uri.query().unwrap_or_default().as_bytes()).collect::<Vec<_>>();
                let param_client_id = query_params.iter().filter(|e| e.0 == "client_id").map(|e| e.1.clone())
                    .next();
                let param_client_id = match param_client_id {
                    Some(param_client_id) => {
                        let param_client_id =
                            <String as std::str::FromStr>::from_str
                                (&param_client_id);
                        match param_client_id {
                            Ok(param_client_id) => Some(param_client_id),
                            Err(e) => return Ok(Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body(Body::from(format!("Couldn't parse query parameter client_id - doesn't match schema: {}", e)))
                                .expect("Unable to create Bad Request response for invalid query parameter client_id")),
                        }
                    },
                    None => None,
                };
                let param_client_id = match param_client_id {
                    Some(param_client_id) => param_client_id,
                    None => return Ok(Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(Body::from("Missing required query parameter client_id"))
                        .expect("Unable to create Bad Request response for missing query parameter client_id")),
                };
                let param_code_challenge = query_params.iter().filter(|e| e.0 == "code_challenge").map(|e| e.1.clone())
                    .next();
                let param_code_challenge = match param_code_challenge {
                    Some(param_code_challenge) => {
                        let param_code_challenge =
                            <String as std::str::FromStr>::from_str
                                (&param_code_challenge);
                        match param_code_challenge {
                            Ok(param_code_challenge) => Some(param_code_challenge),
                            Err(e) => return Ok(Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body(Body::from(format!("Couldn't parse query parameter code_challenge - doesn't match schema: {}", e)))
                                .expect("Unable to create Bad Request response for invalid query parameter code_challenge")),
                        }
                    },
                    None => None,
                };
                let param_code_challenge = match param_code_challenge {
                    Some(param_code_challenge) => param_code_challenge,
                    None => return Ok(Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(Body::from("Missing required query parameter code_challenge"))
                        .expect("Unable to create Bad Request response for missing query parameter code_challenge")),
                };
                let param_code_challenge_method = query_params.iter().filter(|e| e.0 == "code_challenge_method").map(|e| e.1.clone())
                    .next();
                let param_code_challenge_method = match param_code_challenge_method {
                    Some(param_code_challenge_method) => {
                        let param_code_challenge_method =
                            <String as std::str::FromStr>::from_str
                                (&param_code_challenge_method);
                        match param_code_challenge_method {
                            Ok(param_code_challenge_method) => Some(param_code_challenge_method),
                            Err(e) => return Ok(Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body(Body::from(format!("Couldn't parse query parameter code_challenge_method - doesn't match schema: {}", e)))
                                .expect("Unable to create Bad Request response for invalid query parameter code_challenge_method")),
                        }
                    },
                    None => None,
                };
                let param_redirect_uri = query_params.iter().filter(|e| e.0 == "redirect_uri").map(|e| e.1.clone())
                    .next();
                let param_redirect_uri = match param_redirect_uri {
                    Some(param_redirect_uri) => {
                        let param_redirect_uri =
                            <String as std::str::FromStr>::from_str
                                (&param_redirect_uri);
                        match param_redirect_uri {
                            Ok(param_redirect_uri) => Some(param_redirect_uri),
                            Err(e) => return Ok(Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body(Body::from(format!("Couldn't parse query parameter redirect_uri - doesn't match schema: {}", e)))
                                .expect("Unable to create Bad Request response for invalid query parameter redirect_uri")),
                        }
                    },
                    None => None,
                };
                let param_redirect_uri = match param_redirect_uri {
                    Some(param_redirect_uri) => param_redirect_uri,
                    None => return Ok(Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(Body::from("Missing required query parameter redirect_uri"))
                        .expect("Unable to create Bad Request response for missing query parameter redirect_uri")),
                };

                                let result = api_impl.login(
                                            param_client_id,
                                            param_code_challenge,
                                            param_redirect_uri,
                                            param_code_challenge_method,
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        match result {
                                            Ok(rsp) => match rsp {
                                                LoginResponse::Success
                                                    (body)
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(200).expect("Unable to turn 200 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_str("application/links+json")
                                                            .expect("Unable to create Content-Type header for LOGIN_SUCCESS"));
                                                    let body = body;
                                                    *response.body_mut() = Body::from(body);
                                                },
                                                LoginResponse::BadRequest
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(400).expect("Unable to turn 400 into a StatusCode");
                                                },
                                                LoginResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");
                                                },
                                            },
                                            Err(ApiError::NotImplementedError(_)) => {
                                                *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
                                                *response.body_mut() = Body::from(IMPLEMENTATION_NOT_YET_AVAILABLE_ERROR_STRING);
                                            },
                                            // Application code returned an error. This should not happen, as the implementation should return a valid response.
                                            Err(ApiError::UnknownApiError(error_message)) => {
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from(format!("An internal error occurred {}", error_message));
                                            }
                                        }

                                        Ok(response)
            },

            // RequestToken - POST /api/authentication/oauth/tokens
            hyper::Method::POST if path.matched(paths::ID_API_AUTHENTICATION_OAUTH_TOKENS) => {
                // Body parameters (note that non-required body parameters will ignore garbage
                // values, rather than causing a 400 response). Produce warning header and logs for
                // any unused fields.
                let result = body.into_raw().await;
                match result {
                            Ok(body) => {
                                let mut unused_elements = Vec::new();
                                let param_o_auth_token_request: Option<OAuthTokenRequest> = if !body.is_empty() {
                                    let deserializer = &mut serde_json::Deserializer::from_slice(&body);
                                    match serde_ignored::deserialize(deserializer, |path| {
                                            warn!("Ignoring unknown field in body: {}", path);
                                            unused_elements.push(path.to_string());
                                    }) {
                                        Ok(param_o_auth_token_request) => param_o_auth_token_request,
                                        Err(e) => return Ok(Response::builder()
                                                        .status(StatusCode::BAD_REQUEST)
                                                        .body(Body::from(format!("Couldn't parse body parameter OAuthTokenRequest - doesn't match schema: {}", e)))
                                                        .expect("Unable to create Bad Request response for invalid body parameter OAuthTokenRequest due to schema")),
                                    }
                                } else {
                                    None
                                };
                                let param_o_auth_token_request = match param_o_auth_token_request {
                                    Some(param_o_auth_token_request) => param_o_auth_token_request,
                                    None => return Ok(Response::builder()
                                                        .status(StatusCode::BAD_REQUEST)
                                                        .body(Body::from("Missing required body parameter OAuthTokenRequest"))
                                                        .expect("Unable to create Bad Request response for missing body parameter OAuthTokenRequest")),
                                };

                                let result = api_impl.request_token(
                                            param_o_auth_token_request,
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        if !unused_elements.is_empty() {
                                            response.headers_mut().insert(
                                                HeaderName::from_static("warning"),
                                                HeaderValue::from_str(format!("Ignoring unknown fields in body: {:?}", unused_elements).as_str())
                                                    .expect("Unable to create Warning header value"));
                                        }

                                        match result {
                                            Ok(rsp) => match rsp {
                                                RequestTokenResponse::Success
                                                    (body)
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(200).expect("Unable to turn 200 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_str("application/links+json")
                                                            .expect("Unable to create Content-Type header for REQUEST_TOKEN_SUCCESS"));
                                                    let body = body;
                                                    *response.body_mut() = Body::from(body);
                                                },
                                                RequestTokenResponse::BadRequest
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(400).expect("Unable to turn 400 into a StatusCode");
                                                },
                                                RequestTokenResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");
                                                },
                                            },
                                            Err(ApiError::NotImplementedError(_)) => {
                                                *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
                                                *response.body_mut() = Body::from(IMPLEMENTATION_NOT_YET_AVAILABLE_ERROR_STRING);
                                            },
                                            // Application code returned an error. This should not happen, as the implementation should return a valid response.
                                            Err(ApiError::UnknownApiError(error_message)) => {
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from(format!("An internal error occurred {}", error_message));
                                            }
                                        }

                                        Ok(response)
                            },
                            Err(e) => Ok(Response::builder()
                                                .status(StatusCode::BAD_REQUEST)
                                                .body(Body::from(format!("Couldn't read body parameter OAuthTokenRequest: {}", e)))
                                                .expect("Unable to create Bad Request response due to unable to read body parameter OAuthTokenRequest")),
                        }
            },

            // UpdateExtension - PUT /v1/extensions/{extensionId}
            hyper::Method::PUT if path.matched(paths::ID_V1_EXTENSIONS_EXTENSIONID) => {
                {
                    let authorization = match *(&context as &dyn Has<Option<Authorization>>).get() {
                        Some(ref authorization) => authorization,
                        None => return Ok(Response::builder()
                                                .status(StatusCode::FORBIDDEN)
                                                .body(Body::from("Unauthenticated"))
                                                .expect("Unable to create Authentication Forbidden response")),
                    };
                }

                // Path parameters
                let path: &str = uri.path();
                let path_params =
                    paths::REGEX_V1_EXTENSIONS_EXTENSIONID
                    .captures(path)
                    .unwrap_or_else(||
                        panic!("Path {} matched RE V1_EXTENSIONS_EXTENSIONID in set but failed match against \"{}\"", path, paths::REGEX_V1_EXTENSIONS_EXTENSIONID.as_str())
                    );

                let param_extension_id = match percent_encoding::percent_decode(path_params["extensionId"].as_bytes()).decode_utf8() {
                    Ok(param_extension_id) => match param_extension_id.parse::<String>() {
                        Ok(param_extension_id) => param_extension_id,
                        Err(e) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't parse path parameter extensionId: {}", e)))
                                        .expect("Unable to create Bad Request response for invalid path parameter")),
                    },
                    Err(_) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't percent-decode path parameter as UTF-8: {}", &path_params["extensionId"])))
                                        .expect("Unable to create Bad Request response for invalid percent decode"))
                };

                // Body parameters (note that non-required body parameters will ignore garbage
                // values, rather than causing a 400 response). Produce warning header and logs for
                // any unused fields.
                let result = body.into_raw().await;
                match result {
                            Ok(body) => {
                                let mut unused_elements = Vec::new();
                                let param_extension: Option<Extension> = if !body.is_empty() {
                                    let deserializer = &mut serde_json::Deserializer::from_slice(&body);
                                    match serde_ignored::deserialize(deserializer, |path| {
                                            warn!("Ignoring unknown field in body: {}", path);
                                            unused_elements.push(path.to_string());
                                    }) {
                                        Ok(param_extension) => param_extension,
                                        Err(e) => return Ok(Response::builder()
                                                        .status(StatusCode::BAD_REQUEST)
                                                        .body(Body::from(format!("Couldn't parse body parameter Extension - doesn't match schema: {}", e)))
                                                        .expect("Unable to create Bad Request response for invalid body parameter Extension due to schema")),
                                    }
                                } else {
                                    None
                                };
                                let param_extension = match param_extension {
                                    Some(param_extension) => param_extension,
                                    None => return Ok(Response::builder()
                                                        .status(StatusCode::BAD_REQUEST)
                                                        .body(Body::from("Missing required body parameter Extension"))
                                                        .expect("Unable to create Bad Request response for missing body parameter Extension")),
                                };

                                let result = api_impl.update_extension(
                                            param_extension_id,
                                            param_extension,
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        if !unused_elements.is_empty() {
                                            response.headers_mut().insert(
                                                HeaderName::from_static("warning"),
                                                HeaderValue::from_str(format!("Ignoring unknown fields in body: {:?}", unused_elements).as_str())
                                                    .expect("Unable to create Warning header value"));
                                        }

                                        match result {
                                            Ok(rsp) => match rsp {
                                                UpdateExtensionResponse::Success
                                                    (body)
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(200).expect("Unable to turn 200 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_str("application/links+json")
                                                            .expect("Unable to create Content-Type header for UPDATE_EXTENSION_SUCCESS"));
                                                    let body = body;
                                                    *response.body_mut() = Body::from(body);
                                                },
                                                UpdateExtensionResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");
                                                },
                                                UpdateExtensionResponse::Forbidden
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(403).expect("Unable to turn 403 into a StatusCode");
                                                },
                                                UpdateExtensionResponse::NotFound
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(404).expect("Unable to turn 404 into a StatusCode");
                                                },
                                            },
                                            Err(ApiError::NotImplementedError(_)) => {
                                                *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
                                                *response.body_mut() = Body::from(IMPLEMENTATION_NOT_YET_AVAILABLE_ERROR_STRING);
                                            },
                                            // Application code returned an error. This should not happen, as the implementation should return a valid response.
                                            Err(ApiError::UnknownApiError(error_message)) => {
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from(format!("An internal error occurred {}", error_message));
                                            }
                                        }

                                        Ok(response)
                            },
                            Err(e) => Ok(Response::builder()
                                                .status(StatusCode::BAD_REQUEST)
                                                .body(Body::from(format!("Couldn't read body parameter Extension: {}", e)))
                                                .expect("Unable to create Bad Request response due to unable to read body parameter Extension")),
                        }
            },

            // CreateGroup - POST /v1/groups
            hyper::Method::POST if path.matched(paths::ID_V1_GROUPS) => {
                {
                    let authorization = match *(&context as &dyn Has<Option<Authorization>>).get() {
                        Some(ref authorization) => authorization,
                        None => return Ok(Response::builder()
                                                .status(StatusCode::FORBIDDEN)
                                                .body(Body::from("Unauthenticated"))
                                                .expect("Unable to create Authentication Forbidden response")),
                    };
                }

                // Body parameters (note that non-required body parameters will ignore garbage
                // values, rather than causing a 400 response). Produce warning header and logs for
                // any unused fields.
                let result = body.into_raw().await;
                match result {
                            Ok(body) => {
                                let mut unused_elements = Vec::new();
                                let param_group: Option<Group> = if !body.is_empty() {
                                    let deserializer = &mut serde_json::Deserializer::from_slice(&body);
                                    match serde_ignored::deserialize(deserializer, |path| {
                                            warn!("Ignoring unknown field in body: {}", path);
                                            unused_elements.push(path.to_string());
                                    }) {
                                        Ok(param_group) => param_group,
                                        Err(e) => return Ok(Response::builder()
                                                        .status(StatusCode::BAD_REQUEST)
                                                        .body(Body::from(format!("Couldn't parse body parameter Group - doesn't match schema: {}", e)))
                                                        .expect("Unable to create Bad Request response for invalid body parameter Group due to schema")),
                                    }
                                } else {
                                    None
                                };
                                let param_group = match param_group {
                                    Some(param_group) => param_group,
                                    None => return Ok(Response::builder()
                                                        .status(StatusCode::BAD_REQUEST)
                                                        .body(Body::from("Missing required body parameter Group"))
                                                        .expect("Unable to create Bad Request response for missing body parameter Group")),
                                };

                                let result = api_impl.create_group(
                                            param_group,
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        if !unused_elements.is_empty() {
                                            response.headers_mut().insert(
                                                HeaderName::from_static("warning"),
                                                HeaderValue::from_str(format!("Ignoring unknown fields in body: {:?}", unused_elements).as_str())
                                                    .expect("Unable to create Warning header value"));
                                        }

                                        match result {
                                            Ok(rsp) => match rsp {
                                                CreateGroupResponse::Success
                                                    (body)
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(201).expect("Unable to turn 201 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_str("application/links+json")
                                                            .expect("Unable to create Content-Type header for CREATE_GROUP_SUCCESS"));
                                                    let body = body;
                                                    *response.body_mut() = Body::from(body);
                                                },
                                                CreateGroupResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");
                                                },
                                                CreateGroupResponse::Forbidden
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(403).expect("Unable to turn 403 into a StatusCode");
                                                },
                                            },
                                            Err(ApiError::NotImplementedError(_)) => {
                                                *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
                                                *response.body_mut() = Body::from(IMPLEMENTATION_NOT_YET_AVAILABLE_ERROR_STRING);
                                            },
                                            // Application code returned an error. This should not happen, as the implementation should return a valid response.
                                            Err(ApiError::UnknownApiError(error_message)) => {
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from(format!("An internal error occurred {}", error_message));
                                            }
                                        }

                                        Ok(response)
                            },
                            Err(e) => Ok(Response::builder()
                                                .status(StatusCode::BAD_REQUEST)
                                                .body(Body::from(format!("Couldn't read body parameter Group: {}", e)))
                                                .expect("Unable to create Bad Request response due to unable to read body parameter Group")),
                        }
            },

            // DeleteGroup - DELETE /v1/groups/{groupId}
            hyper::Method::DELETE if path.matched(paths::ID_V1_GROUPS_GROUPID) => {
                {
                    let authorization = match *(&context as &dyn Has<Option<Authorization>>).get() {
                        Some(ref authorization) => authorization,
                        None => return Ok(Response::builder()
                                                .status(StatusCode::FORBIDDEN)
                                                .body(Body::from("Unauthenticated"))
                                                .expect("Unable to create Authentication Forbidden response")),
                    };
                }

                // Path parameters
                let path: &str = uri.path();
                let path_params =
                    paths::REGEX_V1_GROUPS_GROUPID
                    .captures(path)
                    .unwrap_or_else(||
                        panic!("Path {} matched RE V1_GROUPS_GROUPID in set but failed match against \"{}\"", path, paths::REGEX_V1_GROUPS_GROUPID.as_str())
                    );

                let param_group_id = match percent_encoding::percent_decode(path_params["groupId"].as_bytes()).decode_utf8() {
                    Ok(param_group_id) => match param_group_id.parse::<String>() {
                        Ok(param_group_id) => param_group_id,
                        Err(e) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't parse path parameter groupId: {}", e)))
                                        .expect("Unable to create Bad Request response for invalid path parameter")),
                    },
                    Err(_) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't percent-decode path parameter as UTF-8: {}", &path_params["groupId"])))
                                        .expect("Unable to create Bad Request response for invalid percent decode"))
                };

                                let result = api_impl.delete_group(
                                            param_group_id,
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        match result {
                                            Ok(rsp) => match rsp {
                                                DeleteGroupResponse::Success
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(204).expect("Unable to turn 204 into a StatusCode");
                                                },
                                                DeleteGroupResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");
                                                },
                                                DeleteGroupResponse::Forbidden
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(403).expect("Unable to turn 403 into a StatusCode");
                                                },
                                                DeleteGroupResponse::NotFound
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(404).expect("Unable to turn 404 into a StatusCode");
                                                },
                                            },
                                            Err(ApiError::NotImplementedError(_)) => {
                                                *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
                                                *response.body_mut() = Body::from(IMPLEMENTATION_NOT_YET_AVAILABLE_ERROR_STRING);
                                            },
                                            // Application code returned an error. This should not happen, as the implementation should return a valid response.
                                            Err(ApiError::UnknownApiError(error_message)) => {
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from(format!("An internal error occurred {}", error_message));
                                            }
                                        }

                                        Ok(response)
            },

            // GetGroup - GET /v1/groups/{groupId}
            hyper::Method::GET if path.matched(paths::ID_V1_GROUPS_GROUPID) => {
                {
                    let authorization = match *(&context as &dyn Has<Option<Authorization>>).get() {
                        Some(ref authorization) => authorization,
                        None => return Ok(Response::builder()
                                                .status(StatusCode::FORBIDDEN)
                                                .body(Body::from("Unauthenticated"))
                                                .expect("Unable to create Authentication Forbidden response")),
                    };
                }

                // Path parameters
                let path: &str = uri.path();
                let path_params =
                    paths::REGEX_V1_GROUPS_GROUPID
                    .captures(path)
                    .unwrap_or_else(||
                        panic!("Path {} matched RE V1_GROUPS_GROUPID in set but failed match against \"{}\"", path, paths::REGEX_V1_GROUPS_GROUPID.as_str())
                    );

                let param_group_id = match percent_encoding::percent_decode(path_params["groupId"].as_bytes()).decode_utf8() {
                    Ok(param_group_id) => match param_group_id.parse::<String>() {
                        Ok(param_group_id) => param_group_id,
                        Err(e) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't parse path parameter groupId: {}", e)))
                                        .expect("Unable to create Bad Request response for invalid path parameter")),
                    },
                    Err(_) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't percent-decode path parameter as UTF-8: {}", &path_params["groupId"])))
                                        .expect("Unable to create Bad Request response for invalid percent decode"))
                };

                                let result = api_impl.get_group(
                                            param_group_id,
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        match result {
                                            Ok(rsp) => match rsp {
                                                GetGroupResponse::Success
                                                    (body)
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(200).expect("Unable to turn 200 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_str("application/links+json")
                                                            .expect("Unable to create Content-Type header for GET_GROUP_SUCCESS"));
                                                    let body = body;
                                                    *response.body_mut() = Body::from(body);
                                                },
                                                GetGroupResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");
                                                },
                                                GetGroupResponse::Forbidden
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(403).expect("Unable to turn 403 into a StatusCode");
                                                },
                                                GetGroupResponse::NotFound
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(404).expect("Unable to turn 404 into a StatusCode");
                                                },
                                            },
                                            Err(ApiError::NotImplementedError(_)) => {
                                                *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
                                                *response.body_mut() = Body::from(IMPLEMENTATION_NOT_YET_AVAILABLE_ERROR_STRING);
                                            },
                                            // Application code returned an error. This should not happen, as the implementation should return a valid response.
                                            Err(ApiError::UnknownApiError(error_message)) => {
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from(format!("An internal error occurred {}", error_message));
                                            }
                                        }

                                        Ok(response)
            },

            // GetGroups - GET /v1/groups
            hyper::Method::GET if path.matched(paths::ID_V1_GROUPS) => {
                {
                    let authorization = match *(&context as &dyn Has<Option<Authorization>>).get() {
                        Some(ref authorization) => authorization,
                        None => return Ok(Response::builder()
                                                .status(StatusCode::FORBIDDEN)
                                                .body(Body::from("Unauthenticated"))
                                                .expect("Unable to create Authentication Forbidden response")),
                    };
                }

                // Query parameters (note that non-required or collection query parameters will ignore garbage values, rather than causing a 400 response)
                let query_params = form_urlencoded::parse(uri.query().unwrap_or_default().as_bytes()).collect::<Vec<_>>();
                let param_limit = query_params.iter().filter(|e| e.0 == "limit").map(|e| e.1.clone())
                    .next();
                let param_limit = match param_limit {
                    Some(param_limit) => {
                        let param_limit =
                            <i32 as std::str::FromStr>::from_str
                                (&param_limit);
                        match param_limit {
                            Ok(param_limit) => Some(param_limit),
                            Err(e) => return Ok(Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body(Body::from(format!("Couldn't parse query parameter limit - doesn't match schema: {}", e)))
                                .expect("Unable to create Bad Request response for invalid query parameter limit")),
                        }
                    },
                    None => None,
                };
                let param_cursor = query_params.iter().filter(|e| e.0 == "cursor").map(|e| e.1.clone())
                    .next();
                let param_cursor = match param_cursor {
                    Some(param_cursor) => {
                        let param_cursor =
                            <String as std::str::FromStr>::from_str
                                (&param_cursor);
                        match param_cursor {
                            Ok(param_cursor) => Some(param_cursor),
                            Err(e) => return Ok(Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body(Body::from(format!("Couldn't parse query parameter cursor - doesn't match schema: {}", e)))
                                .expect("Unable to create Bad Request response for invalid query parameter cursor")),
                        }
                    },
                    None => None,
                };
                let param_filter = query_params.iter().filter(|e| e.0 == "filter").map(|e| e.1.clone())
                    .next();
                let param_filter = match param_filter {
                    Some(param_filter) => {
                        let param_filter =
                            <String as std::str::FromStr>::from_str
                                (&param_filter);
                        match param_filter {
                            Ok(param_filter) => Some(param_filter),
                            Err(e) => return Ok(Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body(Body::from(format!("Couldn't parse query parameter filter - doesn't match schema: {}", e)))
                                .expect("Unable to create Bad Request response for invalid query parameter filter")),
                        }
                    },
                    None => None,
                };

                                let result = api_impl.get_groups(
                                            param_limit,
                                            param_cursor,
                                            param_filter,
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        match result {
                                            Ok(rsp) => match rsp {
                                                GetGroupsResponse::Success
                                                    (body)
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(200).expect("Unable to turn 200 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_str("application/links+json")
                                                            .expect("Unable to create Content-Type header for GET_GROUPS_SUCCESS"));
                                                    let body = body;
                                                    *response.body_mut() = Body::from(body);
                                                },
                                                GetGroupsResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");
                                                },
                                                GetGroupsResponse::Forbidden
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(403).expect("Unable to turn 403 into a StatusCode");
                                                },
                                            },
                                            Err(ApiError::NotImplementedError(_)) => {
                                                *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
                                                *response.body_mut() = Body::from(IMPLEMENTATION_NOT_YET_AVAILABLE_ERROR_STRING);
                                            },
                                            // Application code returned an error. This should not happen, as the implementation should return a valid response.
                                            Err(ApiError::UnknownApiError(error_message)) => {
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from(format!("An internal error occurred {}", error_message));
                                            }
                                        }

                                        Ok(response)
            },

            // UpdateGroup - PUT /v1/groups/{groupId}
            hyper::Method::PUT if path.matched(paths::ID_V1_GROUPS_GROUPID) => {
                {
                    let authorization = match *(&context as &dyn Has<Option<Authorization>>).get() {
                        Some(ref authorization) => authorization,
                        None => return Ok(Response::builder()
                                                .status(StatusCode::FORBIDDEN)
                                                .body(Body::from("Unauthenticated"))
                                                .expect("Unable to create Authentication Forbidden response")),
                    };
                }

                // Path parameters
                let path: &str = uri.path();
                let path_params =
                    paths::REGEX_V1_GROUPS_GROUPID
                    .captures(path)
                    .unwrap_or_else(||
                        panic!("Path {} matched RE V1_GROUPS_GROUPID in set but failed match against \"{}\"", path, paths::REGEX_V1_GROUPS_GROUPID.as_str())
                    );

                let param_group_id = match percent_encoding::percent_decode(path_params["groupId"].as_bytes()).decode_utf8() {
                    Ok(param_group_id) => match param_group_id.parse::<String>() {
                        Ok(param_group_id) => param_group_id,
                        Err(e) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't parse path parameter groupId: {}", e)))
                                        .expect("Unable to create Bad Request response for invalid path parameter")),
                    },
                    Err(_) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't percent-decode path parameter as UTF-8: {}", &path_params["groupId"])))
                                        .expect("Unable to create Bad Request response for invalid percent decode"))
                };

                // Body parameters (note that non-required body parameters will ignore garbage
                // values, rather than causing a 400 response). Produce warning header and logs for
                // any unused fields.
                let result = body.into_raw().await;
                match result {
                            Ok(body) => {
                                let mut unused_elements = Vec::new();
                                let param_group: Option<Group> = if !body.is_empty() {
                                    let deserializer = &mut serde_json::Deserializer::from_slice(&body);
                                    match serde_ignored::deserialize(deserializer, |path| {
                                            warn!("Ignoring unknown field in body: {}", path);
                                            unused_elements.push(path.to_string());
                                    }) {
                                        Ok(param_group) => param_group,
                                        Err(e) => return Ok(Response::builder()
                                                        .status(StatusCode::BAD_REQUEST)
                                                        .body(Body::from(format!("Couldn't parse body parameter Group - doesn't match schema: {}", e)))
                                                        .expect("Unable to create Bad Request response for invalid body parameter Group due to schema")),
                                    }
                                } else {
                                    None
                                };
                                let param_group = match param_group {
                                    Some(param_group) => param_group,
                                    None => return Ok(Response::builder()
                                                        .status(StatusCode::BAD_REQUEST)
                                                        .body(Body::from("Missing required body parameter Group"))
                                                        .expect("Unable to create Bad Request response for missing body parameter Group")),
                                };

                                let result = api_impl.update_group(
                                            param_group_id,
                                            param_group,
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        if !unused_elements.is_empty() {
                                            response.headers_mut().insert(
                                                HeaderName::from_static("warning"),
                                                HeaderValue::from_str(format!("Ignoring unknown fields in body: {:?}", unused_elements).as_str())
                                                    .expect("Unable to create Warning header value"));
                                        }

                                        match result {
                                            Ok(rsp) => match rsp {
                                                UpdateGroupResponse::Success
                                                    (body)
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(200).expect("Unable to turn 200 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_str("application/links+json")
                                                            .expect("Unable to create Content-Type header for UPDATE_GROUP_SUCCESS"));
                                                    let body = body;
                                                    *response.body_mut() = Body::from(body);
                                                },
                                                UpdateGroupResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");
                                                },
                                                UpdateGroupResponse::Forbidden
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(403).expect("Unable to turn 403 into a StatusCode");
                                                },
                                                UpdateGroupResponse::NotFound
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(404).expect("Unable to turn 404 into a StatusCode");
                                                },
                                            },
                                            Err(ApiError::NotImplementedError(_)) => {
                                                *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
                                                *response.body_mut() = Body::from(IMPLEMENTATION_NOT_YET_AVAILABLE_ERROR_STRING);
                                            },
                                            // Application code returned an error. This should not happen, as the implementation should return a valid response.
                                            Err(ApiError::UnknownApiError(error_message)) => {
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from(format!("An internal error occurred {}", error_message));
                                            }
                                        }

                                        Ok(response)
                            },
                            Err(e) => Ok(Response::builder()
                                                .status(StatusCode::BAD_REQUEST)
                                                .body(Body::from(format!("Couldn't read body parameter Group: {}", e)))
                                                .expect("Unable to create Bad Request response due to unable to read body parameter Group")),
                        }
            },

            // GetPermissionedResource - GET /v1/resources/{resourceUri}
            hyper::Method::GET if path.matched(paths::ID_V1_RESOURCES_RESOURCEURI) => {
                {
                    let authorization = match *(&context as &dyn Has<Option<Authorization>>).get() {
                        Some(ref authorization) => authorization,
                        None => return Ok(Response::builder()
                                                .status(StatusCode::FORBIDDEN)
                                                .body(Body::from("Unauthenticated"))
                                                .expect("Unable to create Authentication Forbidden response")),
                    };
                }

                // Path parameters
                let path: &str = uri.path();
                let path_params =
                    paths::REGEX_V1_RESOURCES_RESOURCEURI
                    .captures(path)
                    .unwrap_or_else(||
                        panic!("Path {} matched RE V1_RESOURCES_RESOURCEURI in set but failed match against \"{}\"", path, paths::REGEX_V1_RESOURCES_RESOURCEURI.as_str())
                    );

                let param_resource_uri = match percent_encoding::percent_decode(path_params["resourceUri"].as_bytes()).decode_utf8() {
                    Ok(param_resource_uri) => match param_resource_uri.parse::<String>() {
                        Ok(param_resource_uri) => param_resource_uri,
                        Err(e) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't parse path parameter resourceUri: {}", e)))
                                        .expect("Unable to create Bad Request response for invalid path parameter")),
                    },
                    Err(_) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't percent-decode path parameter as UTF-8: {}", &path_params["resourceUri"])))
                                        .expect("Unable to create Bad Request response for invalid percent decode"))
                };

                                let result = api_impl.get_permissioned_resource(
                                            param_resource_uri,
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        match result {
                                            Ok(rsp) => match rsp {
                                                GetPermissionedResourceResponse::Success
                                                    (body)
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(200).expect("Unable to turn 200 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_str("application/links+json")
                                                            .expect("Unable to create Content-Type header for GET_PERMISSIONED_RESOURCE_SUCCESS"));
                                                    let body = body;
                                                    *response.body_mut() = Body::from(body);
                                                },
                                                GetPermissionedResourceResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");
                                                },
                                                GetPermissionedResourceResponse::NotFound
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(404).expect("Unable to turn 404 into a StatusCode");
                                                },
                                            },
                                            Err(ApiError::NotImplementedError(_)) => {
                                                *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
                                                *response.body_mut() = Body::from(IMPLEMENTATION_NOT_YET_AVAILABLE_ERROR_STRING);
                                            },
                                            // Application code returned an error. This should not happen, as the implementation should return a valid response.
                                            Err(ApiError::UnknownApiError(error_message)) => {
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from(format!("An internal error occurred {}", error_message));
                                            }
                                        }

                                        Ok(response)
            },

            // GetPermissionedResources - GET /v1/resources
            hyper::Method::GET if path.matched(paths::ID_V1_RESOURCES) => {
                {
                    let authorization = match *(&context as &dyn Has<Option<Authorization>>).get() {
                        Some(ref authorization) => authorization,
                        None => return Ok(Response::builder()
                                                .status(StatusCode::FORBIDDEN)
                                                .body(Body::from("Unauthenticated"))
                                                .expect("Unable to create Authentication Forbidden response")),
                    };
                }

                                let result = api_impl.get_permissioned_resources(
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        match result {
                                            Ok(rsp) => match rsp {
                                                GetPermissionedResourcesResponse::Success
                                                    (body)
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(200).expect("Unable to turn 200 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_str("application/links+json")
                                                            .expect("Unable to create Content-Type header for GET_PERMISSIONED_RESOURCES_SUCCESS"));
                                                    let body = body;
                                                    *response.body_mut() = Body::from(body);
                                                },
                                                GetPermissionedResourcesResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");
                                                },
                                            },
                                            Err(ApiError::NotImplementedError(_)) => {
                                                *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
                                                *response.body_mut() = Body::from(IMPLEMENTATION_NOT_YET_AVAILABLE_ERROR_STRING);
                                            },
                                            // Application code returned an error. This should not happen, as the implementation should return a valid response.
                                            Err(ApiError::UnknownApiError(error_message)) => {
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from(format!("An internal error occurred {}", error_message));
                                            }
                                        }

                                        Ok(response)
            },

            // GetResourceUsers - GET /v1/resources/{resourceUri}/users
            hyper::Method::GET if path.matched(paths::ID_V1_RESOURCES_RESOURCEURI_USERS) => {
                {
                    let authorization = match *(&context as &dyn Has<Option<Authorization>>).get() {
                        Some(ref authorization) => authorization,
                        None => return Ok(Response::builder()
                                                .status(StatusCode::FORBIDDEN)
                                                .body(Body::from("Unauthenticated"))
                                                .expect("Unable to create Authentication Forbidden response")),
                    };
                }

                // Path parameters
                let path: &str = uri.path();
                let path_params =
                    paths::REGEX_V1_RESOURCES_RESOURCEURI_USERS
                    .captures(path)
                    .unwrap_or_else(||
                        panic!("Path {} matched RE V1_RESOURCES_RESOURCEURI_USERS in set but failed match against \"{}\"", path, paths::REGEX_V1_RESOURCES_RESOURCEURI_USERS.as_str())
                    );

                let param_resource_uri = match percent_encoding::percent_decode(path_params["resourceUri"].as_bytes()).decode_utf8() {
                    Ok(param_resource_uri) => match param_resource_uri.parse::<String>() {
                        Ok(param_resource_uri) => param_resource_uri,
                        Err(e) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't parse path parameter resourceUri: {}", e)))
                                        .expect("Unable to create Bad Request response for invalid path parameter")),
                    },
                    Err(_) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't percent-decode path parameter as UTF-8: {}", &path_params["resourceUri"])))
                                        .expect("Unable to create Bad Request response for invalid percent decode"))
                };

                // Query parameters (note that non-required or collection query parameters will ignore garbage values, rather than causing a 400 response)
                let query_params = form_urlencoded::parse(uri.query().unwrap_or_default().as_bytes()).collect::<Vec<_>>();
                let param_limit = query_params.iter().filter(|e| e.0 == "limit").map(|e| e.1.clone())
                    .next();
                let param_limit = match param_limit {
                    Some(param_limit) => {
                        let param_limit =
                            <i32 as std::str::FromStr>::from_str
                                (&param_limit);
                        match param_limit {
                            Ok(param_limit) => Some(param_limit),
                            Err(e) => return Ok(Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body(Body::from(format!("Couldn't parse query parameter limit - doesn't match schema: {}", e)))
                                .expect("Unable to create Bad Request response for invalid query parameter limit")),
                        }
                    },
                    None => None,
                };
                let param_cursor = query_params.iter().filter(|e| e.0 == "cursor").map(|e| e.1.clone())
                    .next();
                let param_cursor = match param_cursor {
                    Some(param_cursor) => {
                        let param_cursor =
                            <String as std::str::FromStr>::from_str
                                (&param_cursor);
                        match param_cursor {
                            Ok(param_cursor) => Some(param_cursor),
                            Err(e) => return Ok(Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body(Body::from(format!("Couldn't parse query parameter cursor - doesn't match schema: {}", e)))
                                .expect("Unable to create Bad Request response for invalid query parameter cursor")),
                        }
                    },
                    None => None,
                };

                                let result = api_impl.get_resource_users(
                                            param_resource_uri,
                                            param_limit,
                                            param_cursor,
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        match result {
                                            Ok(rsp) => match rsp {
                                                GetResourceUsersResponse::Success
                                                    (body)
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(200).expect("Unable to turn 200 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_str("application/links+json")
                                                            .expect("Unable to create Content-Type header for GET_RESOURCE_USERS_SUCCESS"));
                                                    let body = body;
                                                    *response.body_mut() = Body::from(body);
                                                },
                                                GetResourceUsersResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");
                                                },
                                            },
                                            Err(ApiError::NotImplementedError(_)) => {
                                                *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
                                                *response.body_mut() = Body::from(IMPLEMENTATION_NOT_YET_AVAILABLE_ERROR_STRING);
                                            },
                                            // Application code returned an error. This should not happen, as the implementation should return a valid response.
                                            Err(ApiError::UnknownApiError(error_message)) => {
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from(format!("An internal error occurred {}", error_message));
                                            }
                                        }

                                        Ok(response)
            },

            // UpdatePermissionedResource - PUT /v1/resources/{resourceUri}
            hyper::Method::PUT if path.matched(paths::ID_V1_RESOURCES_RESOURCEURI) => {
                {
                    let authorization = match *(&context as &dyn Has<Option<Authorization>>).get() {
                        Some(ref authorization) => authorization,
                        None => return Ok(Response::builder()
                                                .status(StatusCode::FORBIDDEN)
                                                .body(Body::from("Unauthenticated"))
                                                .expect("Unable to create Authentication Forbidden response")),
                    };
                }

                // Path parameters
                let path: &str = uri.path();
                let path_params =
                    paths::REGEX_V1_RESOURCES_RESOURCEURI
                    .captures(path)
                    .unwrap_or_else(||
                        panic!("Path {} matched RE V1_RESOURCES_RESOURCEURI in set but failed match against \"{}\"", path, paths::REGEX_V1_RESOURCES_RESOURCEURI.as_str())
                    );

                let param_resource_uri = match percent_encoding::percent_decode(path_params["resourceUri"].as_bytes()).decode_utf8() {
                    Ok(param_resource_uri) => match param_resource_uri.parse::<String>() {
                        Ok(param_resource_uri) => param_resource_uri,
                        Err(e) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't parse path parameter resourceUri: {}", e)))
                                        .expect("Unable to create Bad Request response for invalid path parameter")),
                    },
                    Err(_) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't percent-decode path parameter as UTF-8: {}", &path_params["resourceUri"])))
                                        .expect("Unable to create Bad Request response for invalid percent decode"))
                };

                // Body parameters (note that non-required body parameters will ignore garbage
                // values, rather than causing a 400 response). Produce warning header and logs for
                // any unused fields.
                let result = body.into_raw().await;
                match result {
                            Ok(body) => {
                                let mut unused_elements = Vec::new();
                                let param_permissioned_resource: Option<PermissionedResource> = if !body.is_empty() {
                                    let deserializer = &mut serde_json::Deserializer::from_slice(&body);
                                    match serde_ignored::deserialize(deserializer, |path| {
                                            warn!("Ignoring unknown field in body: {}", path);
                                            unused_elements.push(path.to_string());
                                    }) {
                                        Ok(param_permissioned_resource) => param_permissioned_resource,
                                        Err(e) => return Ok(Response::builder()
                                                        .status(StatusCode::BAD_REQUEST)
                                                        .body(Body::from(format!("Couldn't parse body parameter PermissionedResource - doesn't match schema: {}", e)))
                                                        .expect("Unable to create Bad Request response for invalid body parameter PermissionedResource due to schema")),
                                    }
                                } else {
                                    None
                                };
                                let param_permissioned_resource = match param_permissioned_resource {
                                    Some(param_permissioned_resource) => param_permissioned_resource,
                                    None => return Ok(Response::builder()
                                                        .status(StatusCode::BAD_REQUEST)
                                                        .body(Body::from("Missing required body parameter PermissionedResource"))
                                                        .expect("Unable to create Bad Request response for missing body parameter PermissionedResource")),
                                };

                                let result = api_impl.update_permissioned_resource(
                                            param_resource_uri,
                                            param_permissioned_resource,
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        if !unused_elements.is_empty() {
                                            response.headers_mut().insert(
                                                HeaderName::from_static("warning"),
                                                HeaderValue::from_str(format!("Ignoring unknown fields in body: {:?}", unused_elements).as_str())
                                                    .expect("Unable to create Warning header value"));
                                        }

                                        match result {
                                            Ok(rsp) => match rsp {
                                                UpdatePermissionedResourceResponse::Success
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(200).expect("Unable to turn 200 into a StatusCode");
                                                },
                                                UpdatePermissionedResourceResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");
                                                },
                                                UpdatePermissionedResourceResponse::Forbidden
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(403).expect("Unable to turn 403 into a StatusCode");
                                                },
                                                UpdatePermissionedResourceResponse::NotFound
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(404).expect("Unable to turn 404 into a StatusCode");
                                                },
                                            },
                                            Err(ApiError::NotImplementedError(_)) => {
                                                *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
                                                *response.body_mut() = Body::from(IMPLEMENTATION_NOT_YET_AVAILABLE_ERROR_STRING);
                                            },
                                            // Application code returned an error. This should not happen, as the implementation should return a valid response.
                                            Err(ApiError::UnknownApiError(error_message)) => {
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from(format!("An internal error occurred {}", error_message));
                                            }
                                        }

                                        Ok(response)
                            },
                            Err(e) => Ok(Response::builder()
                                                .status(StatusCode::BAD_REQUEST)
                                                .body(Body::from(format!("Couldn't read body parameter PermissionedResource: {}", e)))
                                                .expect("Unable to create Bad Request response due to unable to read body parameter PermissionedResource")),
                        }
            },

            // CreateRole - POST /v1/roles
            hyper::Method::POST if path.matched(paths::ID_V1_ROLES) => {
                {
                    let authorization = match *(&context as &dyn Has<Option<Authorization>>).get() {
                        Some(ref authorization) => authorization,
                        None => return Ok(Response::builder()
                                                .status(StatusCode::FORBIDDEN)
                                                .body(Body::from("Unauthenticated"))
                                                .expect("Unable to create Authentication Forbidden response")),
                    };
                }

                // Body parameters (note that non-required body parameters will ignore garbage
                // values, rather than causing a 400 response). Produce warning header and logs for
                // any unused fields.
                let result = body.into_raw().await;
                match result {
                            Ok(body) => {
                                let mut unused_elements = Vec::new();
                                let param_role: Option<Role> = if !body.is_empty() {
                                    let deserializer = &mut serde_json::Deserializer::from_slice(&body);
                                    match serde_ignored::deserialize(deserializer, |path| {
                                            warn!("Ignoring unknown field in body: {}", path);
                                            unused_elements.push(path.to_string());
                                    }) {
                                        Ok(param_role) => param_role,
                                        Err(e) => return Ok(Response::builder()
                                                        .status(StatusCode::BAD_REQUEST)
                                                        .body(Body::from(format!("Couldn't parse body parameter Role - doesn't match schema: {}", e)))
                                                        .expect("Unable to create Bad Request response for invalid body parameter Role due to schema")),
                                    }
                                } else {
                                    None
                                };
                                let param_role = match param_role {
                                    Some(param_role) => param_role,
                                    None => return Ok(Response::builder()
                                                        .status(StatusCode::BAD_REQUEST)
                                                        .body(Body::from("Missing required body parameter Role"))
                                                        .expect("Unable to create Bad Request response for missing body parameter Role")),
                                };

                                let result = api_impl.create_role(
                                            param_role,
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        if !unused_elements.is_empty() {
                                            response.headers_mut().insert(
                                                HeaderName::from_static("warning"),
                                                HeaderValue::from_str(format!("Ignoring unknown fields in body: {:?}", unused_elements).as_str())
                                                    .expect("Unable to create Warning header value"));
                                        }

                                        match result {
                                            Ok(rsp) => match rsp {
                                                CreateRoleResponse::Success
                                                    (body)
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(201).expect("Unable to turn 201 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_str("application/links+json")
                                                            .expect("Unable to create Content-Type header for CREATE_ROLE_SUCCESS"));
                                                    let body = body;
                                                    *response.body_mut() = Body::from(body);
                                                },
                                                CreateRoleResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");
                                                },
                                                CreateRoleResponse::Forbidden
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(403).expect("Unable to turn 403 into a StatusCode");
                                                },
                                            },
                                            Err(ApiError::NotImplementedError(_)) => {
                                                *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
                                                *response.body_mut() = Body::from(IMPLEMENTATION_NOT_YET_AVAILABLE_ERROR_STRING);
                                            },
                                            // Application code returned an error. This should not happen, as the implementation should return a valid response.
                                            Err(ApiError::UnknownApiError(error_message)) => {
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from(format!("An internal error occurred {}", error_message));
                                            }
                                        }

                                        Ok(response)
                            },
                            Err(e) => Ok(Response::builder()
                                                .status(StatusCode::BAD_REQUEST)
                                                .body(Body::from(format!("Couldn't read body parameter Role: {}", e)))
                                                .expect("Unable to create Bad Request response due to unable to read body parameter Role")),
                        }
            },

            // DeleteRole - DELETE /v1/roles/{roleId}
            hyper::Method::DELETE if path.matched(paths::ID_V1_ROLES_ROLEID) => {
                {
                    let authorization = match *(&context as &dyn Has<Option<Authorization>>).get() {
                        Some(ref authorization) => authorization,
                        None => return Ok(Response::builder()
                                                .status(StatusCode::FORBIDDEN)
                                                .body(Body::from("Unauthenticated"))
                                                .expect("Unable to create Authentication Forbidden response")),
                    };
                }

                // Path parameters
                let path: &str = uri.path();
                let path_params =
                    paths::REGEX_V1_ROLES_ROLEID
                    .captures(path)
                    .unwrap_or_else(||
                        panic!("Path {} matched RE V1_ROLES_ROLEID in set but failed match against \"{}\"", path, paths::REGEX_V1_ROLES_ROLEID.as_str())
                    );

                let param_role_id = match percent_encoding::percent_decode(path_params["roleId"].as_bytes()).decode_utf8() {
                    Ok(param_role_id) => match param_role_id.parse::<String>() {
                        Ok(param_role_id) => param_role_id,
                        Err(e) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't parse path parameter roleId: {}", e)))
                                        .expect("Unable to create Bad Request response for invalid path parameter")),
                    },
                    Err(_) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't percent-decode path parameter as UTF-8: {}", &path_params["roleId"])))
                                        .expect("Unable to create Bad Request response for invalid percent decode"))
                };

                                let result = api_impl.delete_role(
                                            param_role_id,
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        match result {
                                            Ok(rsp) => match rsp {
                                                DeleteRoleResponse::Success
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(204).expect("Unable to turn 204 into a StatusCode");
                                                },
                                                DeleteRoleResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");
                                                },
                                                DeleteRoleResponse::Forbidden
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(403).expect("Unable to turn 403 into a StatusCode");
                                                },
                                                DeleteRoleResponse::NotFound
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(404).expect("Unable to turn 404 into a StatusCode");
                                                },
                                            },
                                            Err(ApiError::NotImplementedError(_)) => {
                                                *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
                                                *response.body_mut() = Body::from(IMPLEMENTATION_NOT_YET_AVAILABLE_ERROR_STRING);
                                            },
                                            // Application code returned an error. This should not happen, as the implementation should return a valid response.
                                            Err(ApiError::UnknownApiError(error_message)) => {
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from(format!("An internal error occurred {}", error_message));
                                            }
                                        }

                                        Ok(response)
            },

            // GetRole - GET /v1/roles/{roleId}
            hyper::Method::GET if path.matched(paths::ID_V1_ROLES_ROLEID) => {
                {
                    let authorization = match *(&context as &dyn Has<Option<Authorization>>).get() {
                        Some(ref authorization) => authorization,
                        None => return Ok(Response::builder()
                                                .status(StatusCode::FORBIDDEN)
                                                .body(Body::from("Unauthenticated"))
                                                .expect("Unable to create Authentication Forbidden response")),
                    };
                }

                // Path parameters
                let path: &str = uri.path();
                let path_params =
                    paths::REGEX_V1_ROLES_ROLEID
                    .captures(path)
                    .unwrap_or_else(||
                        panic!("Path {} matched RE V1_ROLES_ROLEID in set but failed match against \"{}\"", path, paths::REGEX_V1_ROLES_ROLEID.as_str())
                    );

                let param_role_id = match percent_encoding::percent_decode(path_params["roleId"].as_bytes()).decode_utf8() {
                    Ok(param_role_id) => match param_role_id.parse::<String>() {
                        Ok(param_role_id) => param_role_id,
                        Err(e) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't parse path parameter roleId: {}", e)))
                                        .expect("Unable to create Bad Request response for invalid path parameter")),
                    },
                    Err(_) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't percent-decode path parameter as UTF-8: {}", &path_params["roleId"])))
                                        .expect("Unable to create Bad Request response for invalid percent decode"))
                };

                                let result = api_impl.get_role(
                                            param_role_id,
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        match result {
                                            Ok(rsp) => match rsp {
                                                GetRoleResponse::Success
                                                    (body)
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(200).expect("Unable to turn 200 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_str("application/links+json")
                                                            .expect("Unable to create Content-Type header for GET_ROLE_SUCCESS"));
                                                    let body = body;
                                                    *response.body_mut() = Body::from(body);
                                                },
                                                GetRoleResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");
                                                },
                                                GetRoleResponse::Forbidden
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(403).expect("Unable to turn 403 into a StatusCode");
                                                },
                                                GetRoleResponse::NotFound
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(404).expect("Unable to turn 404 into a StatusCode");
                                                },
                                            },
                                            Err(ApiError::NotImplementedError(_)) => {
                                                *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
                                                *response.body_mut() = Body::from(IMPLEMENTATION_NOT_YET_AVAILABLE_ERROR_STRING);
                                            },
                                            // Application code returned an error. This should not happen, as the implementation should return a valid response.
                                            Err(ApiError::UnknownApiError(error_message)) => {
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from(format!("An internal error occurred {}", error_message));
                                            }
                                        }

                                        Ok(response)
            },

            // GetRoles - GET /v1/roles
            hyper::Method::GET if path.matched(paths::ID_V1_ROLES) => {
                {
                    let authorization = match *(&context as &dyn Has<Option<Authorization>>).get() {
                        Some(ref authorization) => authorization,
                        None => return Ok(Response::builder()
                                                .status(StatusCode::FORBIDDEN)
                                                .body(Body::from("Unauthenticated"))
                                                .expect("Unable to create Authentication Forbidden response")),
                    };
                }

                                let result = api_impl.get_roles(
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        match result {
                                            Ok(rsp) => match rsp {
                                                GetRolesResponse::Success
                                                    (body)
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(200).expect("Unable to turn 200 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_str("application/links+json")
                                                            .expect("Unable to create Content-Type header for GET_ROLES_SUCCESS"));
                                                    let body = body;
                                                    *response.body_mut() = Body::from(body);
                                                },
                                                GetRolesResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");
                                                },
                                                GetRolesResponse::Forbidden
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(403).expect("Unable to turn 403 into a StatusCode");
                                                },
                                            },
                                            Err(ApiError::NotImplementedError(_)) => {
                                                *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
                                                *response.body_mut() = Body::from(IMPLEMENTATION_NOT_YET_AVAILABLE_ERROR_STRING);
                                            },
                                            // Application code returned an error. This should not happen, as the implementation should return a valid response.
                                            Err(ApiError::UnknownApiError(error_message)) => {
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from(format!("An internal error occurred {}", error_message));
                                            }
                                        }

                                        Ok(response)
            },

            // UpdateRole - PUT /v1/roles/{roleId}
            hyper::Method::PUT if path.matched(paths::ID_V1_ROLES_ROLEID) => {
                {
                    let authorization = match *(&context as &dyn Has<Option<Authorization>>).get() {
                        Some(ref authorization) => authorization,
                        None => return Ok(Response::builder()
                                                .status(StatusCode::FORBIDDEN)
                                                .body(Body::from("Unauthenticated"))
                                                .expect("Unable to create Authentication Forbidden response")),
                    };
                }

                // Path parameters
                let path: &str = uri.path();
                let path_params =
                    paths::REGEX_V1_ROLES_ROLEID
                    .captures(path)
                    .unwrap_or_else(||
                        panic!("Path {} matched RE V1_ROLES_ROLEID in set but failed match against \"{}\"", path, paths::REGEX_V1_ROLES_ROLEID.as_str())
                    );

                let param_role_id = match percent_encoding::percent_decode(path_params["roleId"].as_bytes()).decode_utf8() {
                    Ok(param_role_id) => match param_role_id.parse::<String>() {
                        Ok(param_role_id) => param_role_id,
                        Err(e) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't parse path parameter roleId: {}", e)))
                                        .expect("Unable to create Bad Request response for invalid path parameter")),
                    },
                    Err(_) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't percent-decode path parameter as UTF-8: {}", &path_params["roleId"])))
                                        .expect("Unable to create Bad Request response for invalid percent decode"))
                };

                // Body parameters (note that non-required body parameters will ignore garbage
                // values, rather than causing a 400 response). Produce warning header and logs for
                // any unused fields.
                let result = body.into_raw().await;
                match result {
                            Ok(body) => {
                                let mut unused_elements = Vec::new();
                                let param_role: Option<Role> = if !body.is_empty() {
                                    let deserializer = &mut serde_json::Deserializer::from_slice(&body);
                                    match serde_ignored::deserialize(deserializer, |path| {
                                            warn!("Ignoring unknown field in body: {}", path);
                                            unused_elements.push(path.to_string());
                                    }) {
                                        Ok(param_role) => param_role,
                                        Err(e) => return Ok(Response::builder()
                                                        .status(StatusCode::BAD_REQUEST)
                                                        .body(Body::from(format!("Couldn't parse body parameter Role - doesn't match schema: {}", e)))
                                                        .expect("Unable to create Bad Request response for invalid body parameter Role due to schema")),
                                    }
                                } else {
                                    None
                                };
                                let param_role = match param_role {
                                    Some(param_role) => param_role,
                                    None => return Ok(Response::builder()
                                                        .status(StatusCode::BAD_REQUEST)
                                                        .body(Body::from("Missing required body parameter Role"))
                                                        .expect("Unable to create Bad Request response for missing body parameter Role")),
                                };

                                let result = api_impl.update_role(
                                            param_role_id,
                                            param_role,
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        if !unused_elements.is_empty() {
                                            response.headers_mut().insert(
                                                HeaderName::from_static("warning"),
                                                HeaderValue::from_str(format!("Ignoring unknown fields in body: {:?}", unused_elements).as_str())
                                                    .expect("Unable to create Warning header value"));
                                        }

                                        match result {
                                            Ok(rsp) => match rsp {
                                                UpdateRoleResponse::Success
                                                    (body)
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(200).expect("Unable to turn 200 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_str("application/links+json")
                                                            .expect("Unable to create Content-Type header for UPDATE_ROLE_SUCCESS"));
                                                    let body = body;
                                                    *response.body_mut() = Body::from(body);
                                                },
                                                UpdateRoleResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");
                                                },
                                                UpdateRoleResponse::Forbidden
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(403).expect("Unable to turn 403 into a StatusCode");
                                                },
                                                UpdateRoleResponse::NotFound
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(404).expect("Unable to turn 404 into a StatusCode");
                                                },
                                            },
                                            Err(ApiError::NotImplementedError(_)) => {
                                                *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
                                                *response.body_mut() = Body::from(IMPLEMENTATION_NOT_YET_AVAILABLE_ERROR_STRING);
                                            },
                                            // Application code returned an error. This should not happen, as the implementation should return a valid response.
                                            Err(ApiError::UnknownApiError(error_message)) => {
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from(format!("An internal error occurred {}", error_message));
                                            }
                                        }

                                        Ok(response)
                            },
                            Err(e) => Ok(Response::builder()
                                                .status(StatusCode::BAD_REQUEST)
                                                .body(Body::from(format!("Couldn't read body parameter Role: {}", e)))
                                                .expect("Unable to create Bad Request response due to unable to read body parameter Role")),
                        }
            },

            // CreateClient - POST /v1/clients
            hyper::Method::POST if path.matched(paths::ID_V1_CLIENTS) => {
                {
                    let authorization = match *(&context as &dyn Has<Option<Authorization>>).get() {
                        Some(ref authorization) => authorization,
                        None => return Ok(Response::builder()
                                                .status(StatusCode::FORBIDDEN)
                                                .body(Body::from("Unauthenticated"))
                                                .expect("Unable to create Authentication Forbidden response")),
                    };
                }

                // Body parameters (note that non-required body parameters will ignore garbage
                // values, rather than causing a 400 response). Produce warning header and logs for
                // any unused fields.
                let result = body.into_raw().await;
                match result {
                            Ok(body) => {
                                let mut unused_elements = Vec::new();
                                let param_client: Option<Client> = if !body.is_empty() {
                                    let deserializer = &mut serde_json::Deserializer::from_slice(&body);
                                    match serde_ignored::deserialize(deserializer, |path| {
                                            warn!("Ignoring unknown field in body: {}", path);
                                            unused_elements.push(path.to_string());
                                    }) {
                                        Ok(param_client) => param_client,
                                        Err(e) => return Ok(Response::builder()
                                                        .status(StatusCode::BAD_REQUEST)
                                                        .body(Body::from(format!("Couldn't parse body parameter Client - doesn't match schema: {}", e)))
                                                        .expect("Unable to create Bad Request response for invalid body parameter Client due to schema")),
                                    }
                                } else {
                                    None
                                };
                                let param_client = match param_client {
                                    Some(param_client) => param_client,
                                    None => return Ok(Response::builder()
                                                        .status(StatusCode::BAD_REQUEST)
                                                        .body(Body::from("Missing required body parameter Client"))
                                                        .expect("Unable to create Bad Request response for missing body parameter Client")),
                                };

                                let result = api_impl.create_client(
                                            param_client,
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        if !unused_elements.is_empty() {
                                            response.headers_mut().insert(
                                                HeaderName::from_static("warning"),
                                                HeaderValue::from_str(format!("Ignoring unknown fields in body: {:?}", unused_elements).as_str())
                                                    .expect("Unable to create Warning header value"));
                                        }

                                        match result {
                                            Ok(rsp) => match rsp {
                                                CreateClientResponse::Success
                                                    (body)
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(201).expect("Unable to turn 201 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_str("application/links+json")
                                                            .expect("Unable to create Content-Type header for CREATE_CLIENT_SUCCESS"));
                                                    let body = body;
                                                    *response.body_mut() = Body::from(body);
                                                },
                                                CreateClientResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");
                                                },
                                            },
                                            Err(ApiError::NotImplementedError(_)) => {
                                                *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
                                                *response.body_mut() = Body::from(IMPLEMENTATION_NOT_YET_AVAILABLE_ERROR_STRING);
                                            },
                                            // Application code returned an error. This should not happen, as the implementation should return a valid response.
                                            Err(ApiError::UnknownApiError(error_message)) => {
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from(format!("An internal error occurred {}", error_message));
                                            }
                                        }

                                        Ok(response)
                            },
                            Err(e) => Ok(Response::builder()
                                                .status(StatusCode::BAD_REQUEST)
                                                .body(Body::from(format!("Couldn't read body parameter Client: {}", e)))
                                                .expect("Unable to create Bad Request response due to unable to read body parameter Client")),
                        }
            },

            // DeleteAccessKey - DELETE /v1/clients/{clientId}/access-keys/{keyId}
            hyper::Method::DELETE if path.matched(paths::ID_V1_CLIENTS_CLIENTID_ACCESS_KEYS_KEYID) => {
                {
                    let authorization = match *(&context as &dyn Has<Option<Authorization>>).get() {
                        Some(ref authorization) => authorization,
                        None => return Ok(Response::builder()
                                                .status(StatusCode::FORBIDDEN)
                                                .body(Body::from("Unauthenticated"))
                                                .expect("Unable to create Authentication Forbidden response")),
                    };
                }

                // Path parameters
                let path: &str = uri.path();
                let path_params =
                    paths::REGEX_V1_CLIENTS_CLIENTID_ACCESS_KEYS_KEYID
                    .captures(path)
                    .unwrap_or_else(||
                        panic!("Path {} matched RE V1_CLIENTS_CLIENTID_ACCESS_KEYS_KEYID in set but failed match against \"{}\"", path, paths::REGEX_V1_CLIENTS_CLIENTID_ACCESS_KEYS_KEYID.as_str())
                    );

                let param_client_id = match percent_encoding::percent_decode(path_params["clientId"].as_bytes()).decode_utf8() {
                    Ok(param_client_id) => match param_client_id.parse::<String>() {
                        Ok(param_client_id) => param_client_id,
                        Err(e) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't parse path parameter clientId: {}", e)))
                                        .expect("Unable to create Bad Request response for invalid path parameter")),
                    },
                    Err(_) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't percent-decode path parameter as UTF-8: {}", &path_params["clientId"])))
                                        .expect("Unable to create Bad Request response for invalid percent decode"))
                };

                let param_key_id = match percent_encoding::percent_decode(path_params["keyId"].as_bytes()).decode_utf8() {
                    Ok(param_key_id) => match param_key_id.parse::<String>() {
                        Ok(param_key_id) => param_key_id,
                        Err(e) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't parse path parameter keyId: {}", e)))
                                        .expect("Unable to create Bad Request response for invalid path parameter")),
                    },
                    Err(_) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't percent-decode path parameter as UTF-8: {}", &path_params["keyId"])))
                                        .expect("Unable to create Bad Request response for invalid percent decode"))
                };

                                let result = api_impl.delete_access_key(
                                            param_client_id,
                                            param_key_id,
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        match result {
                                            Ok(rsp) => match rsp {
                                                DeleteAccessKeyResponse::Success
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(204).expect("Unable to turn 204 into a StatusCode");
                                                },
                                                DeleteAccessKeyResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");
                                                },
                                                DeleteAccessKeyResponse::Forbidden
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(403).expect("Unable to turn 403 into a StatusCode");
                                                },
                                                DeleteAccessKeyResponse::NotFound
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(404).expect("Unable to turn 404 into a StatusCode");
                                                },
                                            },
                                            Err(ApiError::NotImplementedError(_)) => {
                                                *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
                                                *response.body_mut() = Body::from(IMPLEMENTATION_NOT_YET_AVAILABLE_ERROR_STRING);
                                            },
                                            // Application code returned an error. This should not happen, as the implementation should return a valid response.
                                            Err(ApiError::UnknownApiError(error_message)) => {
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from(format!("An internal error occurred {}", error_message));
                                            }
                                        }

                                        Ok(response)
            },

            // DeleteClient - DELETE /v1/clients/{clientId}
            hyper::Method::DELETE if path.matched(paths::ID_V1_CLIENTS_CLIENTID) => {
                {
                    let authorization = match *(&context as &dyn Has<Option<Authorization>>).get() {
                        Some(ref authorization) => authorization,
                        None => return Ok(Response::builder()
                                                .status(StatusCode::FORBIDDEN)
                                                .body(Body::from("Unauthenticated"))
                                                .expect("Unable to create Authentication Forbidden response")),
                    };
                }

                // Path parameters
                let path: &str = uri.path();
                let path_params =
                    paths::REGEX_V1_CLIENTS_CLIENTID
                    .captures(path)
                    .unwrap_or_else(||
                        panic!("Path {} matched RE V1_CLIENTS_CLIENTID in set but failed match against \"{}\"", path, paths::REGEX_V1_CLIENTS_CLIENTID.as_str())
                    );

                let param_client_id = match percent_encoding::percent_decode(path_params["clientId"].as_bytes()).decode_utf8() {
                    Ok(param_client_id) => match param_client_id.parse::<String>() {
                        Ok(param_client_id) => param_client_id,
                        Err(e) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't parse path parameter clientId: {}", e)))
                                        .expect("Unable to create Bad Request response for invalid path parameter")),
                    },
                    Err(_) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't percent-decode path parameter as UTF-8: {}", &path_params["clientId"])))
                                        .expect("Unable to create Bad Request response for invalid percent decode"))
                };

                                let result = api_impl.delete_client(
                                            param_client_id,
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        match result {
                                            Ok(rsp) => match rsp {
                                                DeleteClientResponse::Success
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(204).expect("Unable to turn 204 into a StatusCode");
                                                },
                                                DeleteClientResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");
                                                },
                                                DeleteClientResponse::Forbidden
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(403).expect("Unable to turn 403 into a StatusCode");
                                                },
                                                DeleteClientResponse::NotFound
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(404).expect("Unable to turn 404 into a StatusCode");
                                                },
                                            },
                                            Err(ApiError::NotImplementedError(_)) => {
                                                *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
                                                *response.body_mut() = Body::from(IMPLEMENTATION_NOT_YET_AVAILABLE_ERROR_STRING);
                                            },
                                            // Application code returned an error. This should not happen, as the implementation should return a valid response.
                                            Err(ApiError::UnknownApiError(error_message)) => {
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from(format!("An internal error occurred {}", error_message));
                                            }
                                        }

                                        Ok(response)
            },

            // GetClient - GET /v1/clients/{clientId}
            hyper::Method::GET if path.matched(paths::ID_V1_CLIENTS_CLIENTID) => {
                {
                    let authorization = match *(&context as &dyn Has<Option<Authorization>>).get() {
                        Some(ref authorization) => authorization,
                        None => return Ok(Response::builder()
                                                .status(StatusCode::FORBIDDEN)
                                                .body(Body::from("Unauthenticated"))
                                                .expect("Unable to create Authentication Forbidden response")),
                    };
                }

                // Path parameters
                let path: &str = uri.path();
                let path_params =
                    paths::REGEX_V1_CLIENTS_CLIENTID
                    .captures(path)
                    .unwrap_or_else(||
                        panic!("Path {} matched RE V1_CLIENTS_CLIENTID in set but failed match against \"{}\"", path, paths::REGEX_V1_CLIENTS_CLIENTID.as_str())
                    );

                let param_client_id = match percent_encoding::percent_decode(path_params["clientId"].as_bytes()).decode_utf8() {
                    Ok(param_client_id) => match param_client_id.parse::<String>() {
                        Ok(param_client_id) => param_client_id,
                        Err(e) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't parse path parameter clientId: {}", e)))
                                        .expect("Unable to create Bad Request response for invalid path parameter")),
                    },
                    Err(_) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't percent-decode path parameter as UTF-8: {}", &path_params["clientId"])))
                                        .expect("Unable to create Bad Request response for invalid percent decode"))
                };

                                let result = api_impl.get_client(
                                            param_client_id,
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        match result {
                                            Ok(rsp) => match rsp {
                                                GetClientResponse::Success
                                                    (body)
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(200).expect("Unable to turn 200 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_str("application/links+json")
                                                            .expect("Unable to create Content-Type header for GET_CLIENT_SUCCESS"));
                                                    let body = body;
                                                    *response.body_mut() = Body::from(body);
                                                },
                                                GetClientResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");
                                                },
                                                GetClientResponse::NotFound
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(404).expect("Unable to turn 404 into a StatusCode");
                                                },
                                            },
                                            Err(ApiError::NotImplementedError(_)) => {
                                                *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
                                                *response.body_mut() = Body::from(IMPLEMENTATION_NOT_YET_AVAILABLE_ERROR_STRING);
                                            },
                                            // Application code returned an error. This should not happen, as the implementation should return a valid response.
                                            Err(ApiError::UnknownApiError(error_message)) => {
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from(format!("An internal error occurred {}", error_message));
                                            }
                                        }

                                        Ok(response)
            },

            // GetClients - GET /v1/clients
            hyper::Method::GET if path.matched(paths::ID_V1_CLIENTS) => {
                {
                    let authorization = match *(&context as &dyn Has<Option<Authorization>>).get() {
                        Some(ref authorization) => authorization,
                        None => return Ok(Response::builder()
                                                .status(StatusCode::FORBIDDEN)
                                                .body(Body::from("Unauthenticated"))
                                                .expect("Unable to create Authentication Forbidden response")),
                    };
                }

                // Query parameters (note that non-required or collection query parameters will ignore garbage values, rather than causing a 400 response)
                let query_params = form_urlencoded::parse(uri.query().unwrap_or_default().as_bytes()).collect::<Vec<_>>();
                let param_limit = query_params.iter().filter(|e| e.0 == "limit").map(|e| e.1.clone())
                    .next();
                let param_limit = match param_limit {
                    Some(param_limit) => {
                        let param_limit =
                            <i32 as std::str::FromStr>::from_str
                                (&param_limit);
                        match param_limit {
                            Ok(param_limit) => Some(param_limit),
                            Err(e) => return Ok(Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body(Body::from(format!("Couldn't parse query parameter limit - doesn't match schema: {}", e)))
                                .expect("Unable to create Bad Request response for invalid query parameter limit")),
                        }
                    },
                    None => None,
                };
                let param_cursor = query_params.iter().filter(|e| e.0 == "cursor").map(|e| e.1.clone())
                    .next();
                let param_cursor = match param_cursor {
                    Some(param_cursor) => {
                        let param_cursor =
                            <String as std::str::FromStr>::from_str
                                (&param_cursor);
                        match param_cursor {
                            Ok(param_cursor) => Some(param_cursor),
                            Err(e) => return Ok(Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body(Body::from(format!("Couldn't parse query parameter cursor - doesn't match schema: {}", e)))
                                .expect("Unable to create Bad Request response for invalid query parameter cursor")),
                        }
                    },
                    None => None,
                };

                                let result = api_impl.get_clients(
                                            param_limit,
                                            param_cursor,
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        match result {
                                            Ok(rsp) => match rsp {
                                                GetClientsResponse::Success
                                                    (body)
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(200).expect("Unable to turn 200 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_str("application/links+json")
                                                            .expect("Unable to create Content-Type header for GET_CLIENTS_SUCCESS"));
                                                    let body = body;
                                                    *response.body_mut() = Body::from(body);
                                                },
                                                GetClientsResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");
                                                },
                                                GetClientsResponse::Forbidden
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(403).expect("Unable to turn 403 into a StatusCode");
                                                },
                                            },
                                            Err(ApiError::NotImplementedError(_)) => {
                                                *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
                                                *response.body_mut() = Body::from(IMPLEMENTATION_NOT_YET_AVAILABLE_ERROR_STRING);
                                            },
                                            // Application code returned an error. This should not happen, as the implementation should return a valid response.
                                            Err(ApiError::UnknownApiError(error_message)) => {
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from(format!("An internal error occurred {}", error_message));
                                            }
                                        }

                                        Ok(response)
            },

            // RequestAccessKey - POST /v1/clients/{clientId}/access-keys
            hyper::Method::POST if path.matched(paths::ID_V1_CLIENTS_CLIENTID_ACCESS_KEYS) => {
                {
                    let authorization = match *(&context as &dyn Has<Option<Authorization>>).get() {
                        Some(ref authorization) => authorization,
                        None => return Ok(Response::builder()
                                                .status(StatusCode::FORBIDDEN)
                                                .body(Body::from("Unauthenticated"))
                                                .expect("Unable to create Authentication Forbidden response")),
                    };
                }

                // Path parameters
                let path: &str = uri.path();
                let path_params =
                    paths::REGEX_V1_CLIENTS_CLIENTID_ACCESS_KEYS
                    .captures(path)
                    .unwrap_or_else(||
                        panic!("Path {} matched RE V1_CLIENTS_CLIENTID_ACCESS_KEYS in set but failed match against \"{}\"", path, paths::REGEX_V1_CLIENTS_CLIENTID_ACCESS_KEYS.as_str())
                    );

                let param_client_id = match percent_encoding::percent_decode(path_params["clientId"].as_bytes()).decode_utf8() {
                    Ok(param_client_id) => match param_client_id.parse::<String>() {
                        Ok(param_client_id) => param_client_id,
                        Err(e) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't parse path parameter clientId: {}", e)))
                                        .expect("Unable to create Bad Request response for invalid path parameter")),
                    },
                    Err(_) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't percent-decode path parameter as UTF-8: {}", &path_params["clientId"])))
                                        .expect("Unable to create Bad Request response for invalid percent decode"))
                };

                                let result = api_impl.request_access_key(
                                            param_client_id,
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        match result {
                                            Ok(rsp) => match rsp {
                                                RequestAccessKeyResponse::Success
                                                    (body)
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(201).expect("Unable to turn 201 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_str("application/links+json")
                                                            .expect("Unable to create Content-Type header for REQUEST_ACCESS_KEY_SUCCESS"));
                                                    let body = body;
                                                    *response.body_mut() = Body::from(body);
                                                },
                                                RequestAccessKeyResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");
                                                },
                                                RequestAccessKeyResponse::Forbidden
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(403).expect("Unable to turn 403 into a StatusCode");
                                                },
                                                RequestAccessKeyResponse::NotFound
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(404).expect("Unable to turn 404 into a StatusCode");
                                                },
                                            },
                                            Err(ApiError::NotImplementedError(_)) => {
                                                *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
                                                *response.body_mut() = Body::from(IMPLEMENTATION_NOT_YET_AVAILABLE_ERROR_STRING);
                                            },
                                            // Application code returned an error. This should not happen, as the implementation should return a valid response.
                                            Err(ApiError::UnknownApiError(error_message)) => {
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from(format!("An internal error occurred {}", error_message));
                                            }
                                        }

                                        Ok(response)
            },

            // UpdateClient - PUT /v1/clients/{clientId}
            hyper::Method::PUT if path.matched(paths::ID_V1_CLIENTS_CLIENTID) => {
                {
                    let authorization = match *(&context as &dyn Has<Option<Authorization>>).get() {
                        Some(ref authorization) => authorization,
                        None => return Ok(Response::builder()
                                                .status(StatusCode::FORBIDDEN)
                                                .body(Body::from("Unauthenticated"))
                                                .expect("Unable to create Authentication Forbidden response")),
                    };
                }

                // Path parameters
                let path: &str = uri.path();
                let path_params =
                    paths::REGEX_V1_CLIENTS_CLIENTID
                    .captures(path)
                    .unwrap_or_else(||
                        panic!("Path {} matched RE V1_CLIENTS_CLIENTID in set but failed match against \"{}\"", path, paths::REGEX_V1_CLIENTS_CLIENTID.as_str())
                    );

                let param_client_id = match percent_encoding::percent_decode(path_params["clientId"].as_bytes()).decode_utf8() {
                    Ok(param_client_id) => match param_client_id.parse::<String>() {
                        Ok(param_client_id) => param_client_id,
                        Err(e) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't parse path parameter clientId: {}", e)))
                                        .expect("Unable to create Bad Request response for invalid path parameter")),
                    },
                    Err(_) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't percent-decode path parameter as UTF-8: {}", &path_params["clientId"])))
                                        .expect("Unable to create Bad Request response for invalid percent decode"))
                };

                // Body parameters (note that non-required body parameters will ignore garbage
                // values, rather than causing a 400 response). Produce warning header and logs for
                // any unused fields.
                let result = body.into_raw().await;
                match result {
                            Ok(body) => {
                                let mut unused_elements = Vec::new();
                                let param_client: Option<Client> = if !body.is_empty() {
                                    let deserializer = &mut serde_json::Deserializer::from_slice(&body);
                                    match serde_ignored::deserialize(deserializer, |path| {
                                            warn!("Ignoring unknown field in body: {}", path);
                                            unused_elements.push(path.to_string());
                                    }) {
                                        Ok(param_client) => param_client,
                                        Err(e) => return Ok(Response::builder()
                                                        .status(StatusCode::BAD_REQUEST)
                                                        .body(Body::from(format!("Couldn't parse body parameter Client - doesn't match schema: {}", e)))
                                                        .expect("Unable to create Bad Request response for invalid body parameter Client due to schema")),
                                    }
                                } else {
                                    None
                                };
                                let param_client = match param_client {
                                    Some(param_client) => param_client,
                                    None => return Ok(Response::builder()
                                                        .status(StatusCode::BAD_REQUEST)
                                                        .body(Body::from("Missing required body parameter Client"))
                                                        .expect("Unable to create Bad Request response for missing body parameter Client")),
                                };

                                let result = api_impl.update_client(
                                            param_client_id,
                                            param_client,
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        if !unused_elements.is_empty() {
                                            response.headers_mut().insert(
                                                HeaderName::from_static("warning"),
                                                HeaderValue::from_str(format!("Ignoring unknown fields in body: {:?}", unused_elements).as_str())
                                                    .expect("Unable to create Warning header value"));
                                        }

                                        match result {
                                            Ok(rsp) => match rsp {
                                                UpdateClientResponse::Success
                                                    (body)
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(200).expect("Unable to turn 200 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_str("application/links+json")
                                                            .expect("Unable to create Content-Type header for UPDATE_CLIENT_SUCCESS"));
                                                    let body = body;
                                                    *response.body_mut() = Body::from(body);
                                                },
                                                UpdateClientResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");
                                                },
                                                UpdateClientResponse::Forbidden
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(403).expect("Unable to turn 403 into a StatusCode");
                                                },
                                                UpdateClientResponse::NotFound
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(404).expect("Unable to turn 404 into a StatusCode");
                                                },
                                            },
                                            Err(ApiError::NotImplementedError(_)) => {
                                                *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
                                                *response.body_mut() = Body::from(IMPLEMENTATION_NOT_YET_AVAILABLE_ERROR_STRING);
                                            },
                                            // Application code returned an error. This should not happen, as the implementation should return a valid response.
                                            Err(ApiError::UnknownApiError(error_message)) => {
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from(format!("An internal error occurred {}", error_message));
                                            }
                                        }

                                        Ok(response)
                            },
                            Err(e) => Ok(Response::builder()
                                                .status(StatusCode::BAD_REQUEST)
                                                .body(Body::from(format!("Couldn't read body parameter Client: {}", e)))
                                                .expect("Unable to create Bad Request response due to unable to read body parameter Client")),
                        }
            },

            // CreateTenant - POST /v1/tenants
            hyper::Method::POST if path.matched(paths::ID_V1_TENANTS) => {
                {
                    let authorization = match *(&context as &dyn Has<Option<Authorization>>).get() {
                        Some(ref authorization) => authorization,
                        None => return Ok(Response::builder()
                                                .status(StatusCode::FORBIDDEN)
                                                .body(Body::from("Unauthenticated"))
                                                .expect("Unable to create Authentication Forbidden response")),
                    };
                }

                // Body parameters (note that non-required body parameters will ignore garbage
                // values, rather than causing a 400 response). Produce warning header and logs for
                // any unused fields.
                let result = body.into_raw().await;
                match result {
                            Ok(body) => {
                                let mut unused_elements = Vec::new();
                                let param_tenant: Option<Tenant> = if !body.is_empty() {
                                    let deserializer = &mut serde_json::Deserializer::from_slice(&body);
                                    match serde_ignored::deserialize(deserializer, |path| {
                                            warn!("Ignoring unknown field in body: {}", path);
                                            unused_elements.push(path.to_string());
                                    }) {
                                        Ok(param_tenant) => param_tenant,
                                        Err(e) => return Ok(Response::builder()
                                                        .status(StatusCode::BAD_REQUEST)
                                                        .body(Body::from(format!("Couldn't parse body parameter Tenant - doesn't match schema: {}", e)))
                                                        .expect("Unable to create Bad Request response for invalid body parameter Tenant due to schema")),
                                    }
                                } else {
                                    None
                                };
                                let param_tenant = match param_tenant {
                                    Some(param_tenant) => param_tenant,
                                    None => return Ok(Response::builder()
                                                        .status(StatusCode::BAD_REQUEST)
                                                        .body(Body::from("Missing required body parameter Tenant"))
                                                        .expect("Unable to create Bad Request response for missing body parameter Tenant")),
                                };

                                let result = api_impl.create_tenant(
                                            param_tenant,
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        if !unused_elements.is_empty() {
                                            response.headers_mut().insert(
                                                HeaderName::from_static("warning"),
                                                HeaderValue::from_str(format!("Ignoring unknown fields in body: {:?}", unused_elements).as_str())
                                                    .expect("Unable to create Warning header value"));
                                        }

                                        match result {
                                            Ok(rsp) => match rsp {
                                                CreateTenantResponse::Success
                                                    (body)
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(201).expect("Unable to turn 201 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_str("application/links+json")
                                                            .expect("Unable to create Content-Type header for CREATE_TENANT_SUCCESS"));
                                                    let body = body;
                                                    *response.body_mut() = Body::from(body);
                                                },
                                                CreateTenantResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");
                                                },
                                                CreateTenantResponse::Forbidden
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(403).expect("Unable to turn 403 into a StatusCode");
                                                },
                                            },
                                            Err(ApiError::NotImplementedError(_)) => {
                                                *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
                                                *response.body_mut() = Body::from(IMPLEMENTATION_NOT_YET_AVAILABLE_ERROR_STRING);
                                            },
                                            // Application code returned an error. This should not happen, as the implementation should return a valid response.
                                            Err(ApiError::UnknownApiError(error_message)) => {
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from(format!("An internal error occurred {}", error_message));
                                            }
                                        }

                                        Ok(response)
                            },
                            Err(e) => Ok(Response::builder()
                                                .status(StatusCode::BAD_REQUEST)
                                                .body(Body::from(format!("Couldn't read body parameter Tenant: {}", e)))
                                                .expect("Unable to create Bad Request response due to unable to read body parameter Tenant")),
                        }
            },

            // DeleteTenant - DELETE /v1/tenants/{tenantId}
            hyper::Method::DELETE if path.matched(paths::ID_V1_TENANTS_TENANTID) => {
                {
                    let authorization = match *(&context as &dyn Has<Option<Authorization>>).get() {
                        Some(ref authorization) => authorization,
                        None => return Ok(Response::builder()
                                                .status(StatusCode::FORBIDDEN)
                                                .body(Body::from("Unauthenticated"))
                                                .expect("Unable to create Authentication Forbidden response")),
                    };
                }

                // Path parameters
                let path: &str = uri.path();
                let path_params =
                    paths::REGEX_V1_TENANTS_TENANTID
                    .captures(path)
                    .unwrap_or_else(||
                        panic!("Path {} matched RE V1_TENANTS_TENANTID in set but failed match against \"{}\"", path, paths::REGEX_V1_TENANTS_TENANTID.as_str())
                    );

                let param_tenant_id = match percent_encoding::percent_decode(path_params["tenantId"].as_bytes()).decode_utf8() {
                    Ok(param_tenant_id) => match param_tenant_id.parse::<String>() {
                        Ok(param_tenant_id) => param_tenant_id,
                        Err(e) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't parse path parameter tenantId: {}", e)))
                                        .expect("Unable to create Bad Request response for invalid path parameter")),
                    },
                    Err(_) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't percent-decode path parameter as UTF-8: {}", &path_params["tenantId"])))
                                        .expect("Unable to create Bad Request response for invalid percent decode"))
                };

                                let result = api_impl.delete_tenant(
                                            param_tenant_id,
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        match result {
                                            Ok(rsp) => match rsp {
                                                DeleteTenantResponse::Success
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(204).expect("Unable to turn 204 into a StatusCode");
                                                },
                                                DeleteTenantResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");
                                                },
                                                DeleteTenantResponse::Forbidden
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(403).expect("Unable to turn 403 into a StatusCode");
                                                },
                                                DeleteTenantResponse::NotFound
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(404).expect("Unable to turn 404 into a StatusCode");
                                                },
                                            },
                                            Err(ApiError::NotImplementedError(_)) => {
                                                *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
                                                *response.body_mut() = Body::from(IMPLEMENTATION_NOT_YET_AVAILABLE_ERROR_STRING);
                                            },
                                            // Application code returned an error. This should not happen, as the implementation should return a valid response.
                                            Err(ApiError::UnknownApiError(error_message)) => {
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from(format!("An internal error occurred {}", error_message));
                                            }
                                        }

                                        Ok(response)
            },

            // GetTenant - GET /v1/tenants/{tenantId}
            hyper::Method::GET if path.matched(paths::ID_V1_TENANTS_TENANTID) => {
                {
                    let authorization = match *(&context as &dyn Has<Option<Authorization>>).get() {
                        Some(ref authorization) => authorization,
                        None => return Ok(Response::builder()
                                                .status(StatusCode::FORBIDDEN)
                                                .body(Body::from("Unauthenticated"))
                                                .expect("Unable to create Authentication Forbidden response")),
                    };
                }

                // Path parameters
                let path: &str = uri.path();
                let path_params =
                    paths::REGEX_V1_TENANTS_TENANTID
                    .captures(path)
                    .unwrap_or_else(||
                        panic!("Path {} matched RE V1_TENANTS_TENANTID in set but failed match against \"{}\"", path, paths::REGEX_V1_TENANTS_TENANTID.as_str())
                    );

                let param_tenant_id = match percent_encoding::percent_decode(path_params["tenantId"].as_bytes()).decode_utf8() {
                    Ok(param_tenant_id) => match param_tenant_id.parse::<String>() {
                        Ok(param_tenant_id) => param_tenant_id,
                        Err(e) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't parse path parameter tenantId: {}", e)))
                                        .expect("Unable to create Bad Request response for invalid path parameter")),
                    },
                    Err(_) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't percent-decode path parameter as UTF-8: {}", &path_params["tenantId"])))
                                        .expect("Unable to create Bad Request response for invalid percent decode"))
                };

                                let result = api_impl.get_tenant(
                                            param_tenant_id,
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        match result {
                                            Ok(rsp) => match rsp {
                                                GetTenantResponse::Success
                                                    (body)
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(200).expect("Unable to turn 200 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_str("application/links+json")
                                                            .expect("Unable to create Content-Type header for GET_TENANT_SUCCESS"));
                                                    let body = body;
                                                    *response.body_mut() = Body::from(body);
                                                },
                                                GetTenantResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");
                                                },
                                                GetTenantResponse::Forbidden
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(403).expect("Unable to turn 403 into a StatusCode");
                                                },
                                                GetTenantResponse::NotFound
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(404).expect("Unable to turn 404 into a StatusCode");
                                                },
                                            },
                                            Err(ApiError::NotImplementedError(_)) => {
                                                *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
                                                *response.body_mut() = Body::from(IMPLEMENTATION_NOT_YET_AVAILABLE_ERROR_STRING);
                                            },
                                            // Application code returned an error. This should not happen, as the implementation should return a valid response.
                                            Err(ApiError::UnknownApiError(error_message)) => {
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from(format!("An internal error occurred {}", error_message));
                                            }
                                        }

                                        Ok(response)
            },

            // GetTenants - GET /v1/tenants
            hyper::Method::GET if path.matched(paths::ID_V1_TENANTS) => {
                {
                    let authorization = match *(&context as &dyn Has<Option<Authorization>>).get() {
                        Some(ref authorization) => authorization,
                        None => return Ok(Response::builder()
                                                .status(StatusCode::FORBIDDEN)
                                                .body(Body::from("Unauthenticated"))
                                                .expect("Unable to create Authentication Forbidden response")),
                    };
                }

                                let result = api_impl.get_tenants(
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        match result {
                                            Ok(rsp) => match rsp {
                                                GetTenantsResponse::Success
                                                    (body)
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(200).expect("Unable to turn 200 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_str("application/links+json")
                                                            .expect("Unable to create Content-Type header for GET_TENANTS_SUCCESS"));
                                                    let body = body;
                                                    *response.body_mut() = Body::from(body);
                                                },
                                                GetTenantsResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");
                                                },
                                                GetTenantsResponse::Forbidden
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(403).expect("Unable to turn 403 into a StatusCode");
                                                },
                                            },
                                            Err(ApiError::NotImplementedError(_)) => {
                                                *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
                                                *response.body_mut() = Body::from(IMPLEMENTATION_NOT_YET_AVAILABLE_ERROR_STRING);
                                            },
                                            // Application code returned an error. This should not happen, as the implementation should return a valid response.
                                            Err(ApiError::UnknownApiError(error_message)) => {
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from(format!("An internal error occurred {}", error_message));
                                            }
                                        }

                                        Ok(response)
            },

            // UpdateTenant - PUT /v1/tenants/{tenantId}
            hyper::Method::PUT if path.matched(paths::ID_V1_TENANTS_TENANTID) => {
                {
                    let authorization = match *(&context as &dyn Has<Option<Authorization>>).get() {
                        Some(ref authorization) => authorization,
                        None => return Ok(Response::builder()
                                                .status(StatusCode::FORBIDDEN)
                                                .body(Body::from("Unauthenticated"))
                                                .expect("Unable to create Authentication Forbidden response")),
                    };
                }

                // Path parameters
                let path: &str = uri.path();
                let path_params =
                    paths::REGEX_V1_TENANTS_TENANTID
                    .captures(path)
                    .unwrap_or_else(||
                        panic!("Path {} matched RE V1_TENANTS_TENANTID in set but failed match against \"{}\"", path, paths::REGEX_V1_TENANTS_TENANTID.as_str())
                    );

                let param_tenant_id = match percent_encoding::percent_decode(path_params["tenantId"].as_bytes()).decode_utf8() {
                    Ok(param_tenant_id) => match param_tenant_id.parse::<String>() {
                        Ok(param_tenant_id) => param_tenant_id,
                        Err(e) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't parse path parameter tenantId: {}", e)))
                                        .expect("Unable to create Bad Request response for invalid path parameter")),
                    },
                    Err(_) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't percent-decode path parameter as UTF-8: {}", &path_params["tenantId"])))
                                        .expect("Unable to create Bad Request response for invalid percent decode"))
                };

                // Body parameters (note that non-required body parameters will ignore garbage
                // values, rather than causing a 400 response). Produce warning header and logs for
                // any unused fields.
                let result = body.into_raw().await;
                match result {
                            Ok(body) => {
                                let mut unused_elements = Vec::new();
                                let param_tenant: Option<Tenant> = if !body.is_empty() {
                                    let deserializer = &mut serde_json::Deserializer::from_slice(&body);
                                    match serde_ignored::deserialize(deserializer, |path| {
                                            warn!("Ignoring unknown field in body: {}", path);
                                            unused_elements.push(path.to_string());
                                    }) {
                                        Ok(param_tenant) => param_tenant,
                                        Err(e) => return Ok(Response::builder()
                                                        .status(StatusCode::BAD_REQUEST)
                                                        .body(Body::from(format!("Couldn't parse body parameter Tenant - doesn't match schema: {}", e)))
                                                        .expect("Unable to create Bad Request response for invalid body parameter Tenant due to schema")),
                                    }
                                } else {
                                    None
                                };
                                let param_tenant = match param_tenant {
                                    Some(param_tenant) => param_tenant,
                                    None => return Ok(Response::builder()
                                                        .status(StatusCode::BAD_REQUEST)
                                                        .body(Body::from("Missing required body parameter Tenant"))
                                                        .expect("Unable to create Bad Request response for missing body parameter Tenant")),
                                };

                                let result = api_impl.update_tenant(
                                            param_tenant_id,
                                            param_tenant,
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        if !unused_elements.is_empty() {
                                            response.headers_mut().insert(
                                                HeaderName::from_static("warning"),
                                                HeaderValue::from_str(format!("Ignoring unknown fields in body: {:?}", unused_elements).as_str())
                                                    .expect("Unable to create Warning header value"));
                                        }

                                        match result {
                                            Ok(rsp) => match rsp {
                                                UpdateTenantResponse::Success
                                                    (body)
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(200).expect("Unable to turn 200 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_str("application/links+json")
                                                            .expect("Unable to create Content-Type header for UPDATE_TENANT_SUCCESS"));
                                                    let body = body;
                                                    *response.body_mut() = Body::from(body);
                                                },
                                                UpdateTenantResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");
                                                },
                                                UpdateTenantResponse::Forbidden
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(403).expect("Unable to turn 403 into a StatusCode");
                                                },
                                                UpdateTenantResponse::NotFound
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(404).expect("Unable to turn 404 into a StatusCode");
                                                },
                                            },
                                            Err(ApiError::NotImplementedError(_)) => {
                                                *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
                                                *response.body_mut() = Body::from(IMPLEMENTATION_NOT_YET_AVAILABLE_ERROR_STRING);
                                            },
                                            // Application code returned an error. This should not happen, as the implementation should return a valid response.
                                            Err(ApiError::UnknownApiError(error_message)) => {
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from(format!("An internal error occurred {}", error_message));
                                            }
                                        }

                                        Ok(response)
                            },
                            Err(e) => Ok(Response::builder()
                                                .status(StatusCode::BAD_REQUEST)
                                                .body(Body::from(format!("Couldn't read body parameter Tenant: {}", e)))
                                                .expect("Unable to create Bad Request response due to unable to read body parameter Tenant")),
                        }
            },

            // AuthorizeUser - GET /v1/users/{userId}/resources/{resourceUri}/permissions/{permission}
            hyper::Method::GET if path.matched(paths::ID_V1_USERS_USERID_RESOURCES_RESOURCEURI_PERMISSIONS_PERMISSION) => {
                {
                    let authorization = match *(&context as &dyn Has<Option<Authorization>>).get() {
                        Some(ref authorization) => authorization,
                        None => return Ok(Response::builder()
                                                .status(StatusCode::FORBIDDEN)
                                                .body(Body::from("Unauthenticated"))
                                                .expect("Unable to create Authentication Forbidden response")),
                    };
                }

                // Path parameters
                let path: &str = uri.path();
                let path_params =
                    paths::REGEX_V1_USERS_USERID_RESOURCES_RESOURCEURI_PERMISSIONS_PERMISSION
                    .captures(path)
                    .unwrap_or_else(||
                        panic!("Path {} matched RE V1_USERS_USERID_RESOURCES_RESOURCEURI_PERMISSIONS_PERMISSION in set but failed match against \"{}\"", path, paths::REGEX_V1_USERS_USERID_RESOURCES_RESOURCEURI_PERMISSIONS_PERMISSION.as_str())
                    );

                let param_user_id = match percent_encoding::percent_decode(path_params["userId"].as_bytes()).decode_utf8() {
                    Ok(param_user_id) => match param_user_id.parse::<String>() {
                        Ok(param_user_id) => param_user_id,
                        Err(e) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't parse path parameter userId: {}", e)))
                                        .expect("Unable to create Bad Request response for invalid path parameter")),
                    },
                    Err(_) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't percent-decode path parameter as UTF-8: {}", &path_params["userId"])))
                                        .expect("Unable to create Bad Request response for invalid percent decode"))
                };

                let param_resource_uri = match percent_encoding::percent_decode(path_params["resourceUri"].as_bytes()).decode_utf8() {
                    Ok(param_resource_uri) => match param_resource_uri.parse::<String>() {
                        Ok(param_resource_uri) => param_resource_uri,
                        Err(e) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't parse path parameter resourceUri: {}", e)))
                                        .expect("Unable to create Bad Request response for invalid path parameter")),
                    },
                    Err(_) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't percent-decode path parameter as UTF-8: {}", &path_params["resourceUri"])))
                                        .expect("Unable to create Bad Request response for invalid percent decode"))
                };

                let param_permission = match percent_encoding::percent_decode(path_params["permission"].as_bytes()).decode_utf8() {
                    Ok(param_permission) => match param_permission.parse::<String>() {
                        Ok(param_permission) => param_permission,
                        Err(e) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't parse path parameter permission: {}", e)))
                                        .expect("Unable to create Bad Request response for invalid path parameter")),
                    },
                    Err(_) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't percent-decode path parameter as UTF-8: {}", &path_params["permission"])))
                                        .expect("Unable to create Bad Request response for invalid percent decode"))
                };

                                let result = api_impl.authorize_user(
                                            param_user_id,
                                            param_resource_uri,
                                            param_permission,
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        match result {
                                            Ok(rsp) => match rsp {
                                                AuthorizeUserResponse::Success
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(200).expect("Unable to turn 200 into a StatusCode");
                                                },
                                                AuthorizeUserResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");
                                                },
                                                AuthorizeUserResponse::Forbidden
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(403).expect("Unable to turn 403 into a StatusCode");
                                                },
                                                AuthorizeUserResponse::NotFound
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(404).expect("Unable to turn 404 into a StatusCode");
                                                },
                                            },
                                            Err(ApiError::NotImplementedError(_)) => {
                                                *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
                                                *response.body_mut() = Body::from(IMPLEMENTATION_NOT_YET_AVAILABLE_ERROR_STRING);
                                            },
                                            // Application code returned an error. This should not happen, as the implementation should return a valid response.
                                            Err(ApiError::UnknownApiError(error_message)) => {
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from(format!("An internal error occurred {}", error_message));
                                            }
                                        }

                                        Ok(response)
            },

            // GetUserPermissionsForResource - GET /v1/users/{userId}/resources/{resourceUri}/permissions
            hyper::Method::GET if path.matched(paths::ID_V1_USERS_USERID_RESOURCES_RESOURCEURI_PERMISSIONS) => {
                {
                    let authorization = match *(&context as &dyn Has<Option<Authorization>>).get() {
                        Some(ref authorization) => authorization,
                        None => return Ok(Response::builder()
                                                .status(StatusCode::FORBIDDEN)
                                                .body(Body::from("Unauthenticated"))
                                                .expect("Unable to create Authentication Forbidden response")),
                    };
                }

                // Path parameters
                let path: &str = uri.path();
                let path_params =
                    paths::REGEX_V1_USERS_USERID_RESOURCES_RESOURCEURI_PERMISSIONS
                    .captures(path)
                    .unwrap_or_else(||
                        panic!("Path {} matched RE V1_USERS_USERID_RESOURCES_RESOURCEURI_PERMISSIONS in set but failed match against \"{}\"", path, paths::REGEX_V1_USERS_USERID_RESOURCES_RESOURCEURI_PERMISSIONS.as_str())
                    );

                let param_user_id = match percent_encoding::percent_decode(path_params["userId"].as_bytes()).decode_utf8() {
                    Ok(param_user_id) => match param_user_id.parse::<String>() {
                        Ok(param_user_id) => param_user_id,
                        Err(e) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't parse path parameter userId: {}", e)))
                                        .expect("Unable to create Bad Request response for invalid path parameter")),
                    },
                    Err(_) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't percent-decode path parameter as UTF-8: {}", &path_params["userId"])))
                                        .expect("Unable to create Bad Request response for invalid percent decode"))
                };

                let param_resource_uri = match percent_encoding::percent_decode(path_params["resourceUri"].as_bytes()).decode_utf8() {
                    Ok(param_resource_uri) => match param_resource_uri.parse::<String>() {
                        Ok(param_resource_uri) => param_resource_uri,
                        Err(e) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't parse path parameter resourceUri: {}", e)))
                                        .expect("Unable to create Bad Request response for invalid path parameter")),
                    },
                    Err(_) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't percent-decode path parameter as UTF-8: {}", &path_params["resourceUri"])))
                                        .expect("Unable to create Bad Request response for invalid percent decode"))
                };

                                let result = api_impl.get_user_permissions_for_resource(
                                            param_user_id,
                                            param_resource_uri,
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        match result {
                                            Ok(rsp) => match rsp {
                                                GetUserPermissionsForResourceResponse::Success
                                                    (body)
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(200).expect("Unable to turn 200 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_str("application/links+json")
                                                            .expect("Unable to create Content-Type header for GET_USER_PERMISSIONS_FOR_RESOURCE_SUCCESS"));
                                                    let body = body;
                                                    *response.body_mut() = Body::from(body);
                                                },
                                                GetUserPermissionsForResourceResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");
                                                },
                                                GetUserPermissionsForResourceResponse::NotFound
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(404).expect("Unable to turn 404 into a StatusCode");
                                                },
                                            },
                                            Err(ApiError::NotImplementedError(_)) => {
                                                *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
                                                *response.body_mut() = Body::from(IMPLEMENTATION_NOT_YET_AVAILABLE_ERROR_STRING);
                                            },
                                            // Application code returned an error. This should not happen, as the implementation should return a valid response.
                                            Err(ApiError::UnknownApiError(error_message)) => {
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from(format!("An internal error occurred {}", error_message));
                                            }
                                        }

                                        Ok(response)
            },

            // GetUserResources - GET /v1/users/{userId}/resources
            hyper::Method::GET if path.matched(paths::ID_V1_USERS_USERID_RESOURCES) => {
                {
                    let authorization = match *(&context as &dyn Has<Option<Authorization>>).get() {
                        Some(ref authorization) => authorization,
                        None => return Ok(Response::builder()
                                                .status(StatusCode::FORBIDDEN)
                                                .body(Body::from("Unauthenticated"))
                                                .expect("Unable to create Authentication Forbidden response")),
                    };
                }

                // Path parameters
                let path: &str = uri.path();
                let path_params =
                    paths::REGEX_V1_USERS_USERID_RESOURCES
                    .captures(path)
                    .unwrap_or_else(||
                        panic!("Path {} matched RE V1_USERS_USERID_RESOURCES in set but failed match against \"{}\"", path, paths::REGEX_V1_USERS_USERID_RESOURCES.as_str())
                    );

                let param_user_id = match percent_encoding::percent_decode(path_params["userId"].as_bytes()).decode_utf8() {
                    Ok(param_user_id) => match param_user_id.parse::<String>() {
                        Ok(param_user_id) => param_user_id,
                        Err(e) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't parse path parameter userId: {}", e)))
                                        .expect("Unable to create Bad Request response for invalid path parameter")),
                    },
                    Err(_) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't percent-decode path parameter as UTF-8: {}", &path_params["userId"])))
                                        .expect("Unable to create Bad Request response for invalid percent decode"))
                };

                // Query parameters (note that non-required or collection query parameters will ignore garbage values, rather than causing a 400 response)
                let query_params = form_urlencoded::parse(uri.query().unwrap_or_default().as_bytes()).collect::<Vec<_>>();
                let param_resource_uri = query_params.iter().filter(|e| e.0 == "resourceUri").map(|e| e.1.clone())
                    .next();
                let param_resource_uri = match param_resource_uri {
                    Some(param_resource_uri) => {
                        let param_resource_uri =
                            <String as std::str::FromStr>::from_str
                                (&param_resource_uri);
                        match param_resource_uri {
                            Ok(param_resource_uri) => Some(param_resource_uri),
                            Err(e) => return Ok(Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body(Body::from(format!("Couldn't parse query parameter resourceUri - doesn't match schema: {}", e)))
                                .expect("Unable to create Bad Request response for invalid query parameter resourceUri")),
                        }
                    },
                    None => None,
                };
                let param_collection_configuration = query_params.iter().filter(|e| e.0 == "collectionConfiguration").map(|e| e.1.clone())
                    .next();
                let param_collection_configuration = match param_collection_configuration {
                    Some(param_collection_configuration) => {
                        let param_collection_configuration =
                            <String as std::str::FromStr>::from_str
                                (&param_collection_configuration);
                        match param_collection_configuration {
                            Ok(param_collection_configuration) => Some(param_collection_configuration),
                            Err(e) => return Ok(Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body(Body::from(format!("Couldn't parse query parameter collectionConfiguration - doesn't match schema: {}", e)))
                                .expect("Unable to create Bad Request response for invalid query parameter collectionConfiguration")),
                        }
                    },
                    None => None,
                };
                let param_permissions = query_params.iter().filter(|e| e.0 == "permissions").map(|e| e.1.clone())
                    .next();
                let param_permissions = match param_permissions {
                    Some(param_permissions) => {
                        let param_permissions =
                            <String as std::str::FromStr>::from_str
                                (&param_permissions);
                        match param_permissions {
                            Ok(param_permissions) => Some(param_permissions),
                            Err(e) => return Ok(Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body(Body::from(format!("Couldn't parse query parameter permissions - doesn't match schema: {}", e)))
                                .expect("Unable to create Bad Request response for invalid query parameter permissions")),
                        }
                    },
                    None => None,
                };
                let param_limit = query_params.iter().filter(|e| e.0 == "limit").map(|e| e.1.clone())
                    .next();
                let param_limit = match param_limit {
                    Some(param_limit) => {
                        let param_limit =
                            <i32 as std::str::FromStr>::from_str
                                (&param_limit);
                        match param_limit {
                            Ok(param_limit) => Some(param_limit),
                            Err(e) => return Ok(Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body(Body::from(format!("Couldn't parse query parameter limit - doesn't match schema: {}", e)))
                                .expect("Unable to create Bad Request response for invalid query parameter limit")),
                        }
                    },
                    None => None,
                };
                let param_cursor = query_params.iter().filter(|e| e.0 == "cursor").map(|e| e.1.clone())
                    .next();
                let param_cursor = match param_cursor {
                    Some(param_cursor) => {
                        let param_cursor =
                            <String as std::str::FromStr>::from_str
                                (&param_cursor);
                        match param_cursor {
                            Ok(param_cursor) => Some(param_cursor),
                            Err(e) => return Ok(Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body(Body::from(format!("Couldn't parse query parameter cursor - doesn't match schema: {}", e)))
                                .expect("Unable to create Bad Request response for invalid query parameter cursor")),
                        }
                    },
                    None => None,
                };

                                let result = api_impl.get_user_resources(
                                            param_user_id,
                                            param_resource_uri,
                                            param_collection_configuration,
                                            param_permissions,
                                            param_limit,
                                            param_cursor,
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        match result {
                                            Ok(rsp) => match rsp {
                                                GetUserResourcesResponse::Success
                                                    (body)
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(200).expect("Unable to turn 200 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_str("application/links+json")
                                                            .expect("Unable to create Content-Type header for GET_USER_RESOURCES_SUCCESS"));
                                                    let body = body;
                                                    *response.body_mut() = Body::from(body);
                                                },
                                                GetUserResourcesResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");
                                                },
                                            },
                                            Err(ApiError::NotImplementedError(_)) => {
                                                *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
                                                *response.body_mut() = Body::from(IMPLEMENTATION_NOT_YET_AVAILABLE_ERROR_STRING);
                                            },
                                            // Application code returned an error. This should not happen, as the implementation should return a valid response.
                                            Err(ApiError::UnknownApiError(error_message)) => {
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from(format!("An internal error occurred {}", error_message));
                                            }
                                        }

                                        Ok(response)
            },

            // GetUserRolesForResource - GET /v1/users/{userId}/resources/{resourceUri}/roles
            hyper::Method::GET if path.matched(paths::ID_V1_USERS_USERID_RESOURCES_RESOURCEURI_ROLES) => {
                {
                    let authorization = match *(&context as &dyn Has<Option<Authorization>>).get() {
                        Some(ref authorization) => authorization,
                        None => return Ok(Response::builder()
                                                .status(StatusCode::FORBIDDEN)
                                                .body(Body::from("Unauthenticated"))
                                                .expect("Unable to create Authentication Forbidden response")),
                    };
                }

                // Path parameters
                let path: &str = uri.path();
                let path_params =
                    paths::REGEX_V1_USERS_USERID_RESOURCES_RESOURCEURI_ROLES
                    .captures(path)
                    .unwrap_or_else(||
                        panic!("Path {} matched RE V1_USERS_USERID_RESOURCES_RESOURCEURI_ROLES in set but failed match against \"{}\"", path, paths::REGEX_V1_USERS_USERID_RESOURCES_RESOURCEURI_ROLES.as_str())
                    );

                let param_user_id = match percent_encoding::percent_decode(path_params["userId"].as_bytes()).decode_utf8() {
                    Ok(param_user_id) => match param_user_id.parse::<String>() {
                        Ok(param_user_id) => param_user_id,
                        Err(e) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't parse path parameter userId: {}", e)))
                                        .expect("Unable to create Bad Request response for invalid path parameter")),
                    },
                    Err(_) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't percent-decode path parameter as UTF-8: {}", &path_params["userId"])))
                                        .expect("Unable to create Bad Request response for invalid percent decode"))
                };

                let param_resource_uri = match percent_encoding::percent_decode(path_params["resourceUri"].as_bytes()).decode_utf8() {
                    Ok(param_resource_uri) => match param_resource_uri.parse::<String>() {
                        Ok(param_resource_uri) => param_resource_uri,
                        Err(e) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't parse path parameter resourceUri: {}", e)))
                                        .expect("Unable to create Bad Request response for invalid path parameter")),
                    },
                    Err(_) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't percent-decode path parameter as UTF-8: {}", &path_params["resourceUri"])))
                                        .expect("Unable to create Bad Request response for invalid percent decode"))
                };

                                let result = api_impl.get_user_roles_for_resource(
                                            param_user_id,
                                            param_resource_uri,
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        match result {
                                            Ok(rsp) => match rsp {
                                                GetUserRolesForResourceResponse::Success
                                                    (body)
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(200).expect("Unable to turn 200 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_str("application/links+json")
                                                            .expect("Unable to create Content-Type header for GET_USER_ROLES_FOR_RESOURCE_SUCCESS"));
                                                    let body = body;
                                                    *response.body_mut() = Body::from(body);
                                                },
                                                GetUserRolesForResourceResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");
                                                },
                                                GetUserRolesForResourceResponse::NotFound
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(404).expect("Unable to turn 404 into a StatusCode");
                                                },
                                            },
                                            Err(ApiError::NotImplementedError(_)) => {
                                                *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
                                                *response.body_mut() = Body::from(IMPLEMENTATION_NOT_YET_AVAILABLE_ERROR_STRING);
                                            },
                                            // Application code returned an error. This should not happen, as the implementation should return a valid response.
                                            Err(ApiError::UnknownApiError(error_message)) => {
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from(format!("An internal error occurred {}", error_message));
                                            }
                                        }

                                        Ok(response)
            },

            // DeleteUser - DELETE /v1/users/{userId}
            hyper::Method::DELETE if path.matched(paths::ID_V1_USERS_USERID) => {
                {
                    let authorization = match *(&context as &dyn Has<Option<Authorization>>).get() {
                        Some(ref authorization) => authorization,
                        None => return Ok(Response::builder()
                                                .status(StatusCode::FORBIDDEN)
                                                .body(Body::from("Unauthenticated"))
                                                .expect("Unable to create Authentication Forbidden response")),
                    };
                }

                // Path parameters
                let path: &str = uri.path();
                let path_params =
                    paths::REGEX_V1_USERS_USERID
                    .captures(path)
                    .unwrap_or_else(||
                        panic!("Path {} matched RE V1_USERS_USERID in set but failed match against \"{}\"", path, paths::REGEX_V1_USERS_USERID.as_str())
                    );

                let param_user_id = match percent_encoding::percent_decode(path_params["userId"].as_bytes()).decode_utf8() {
                    Ok(param_user_id) => match param_user_id.parse::<String>() {
                        Ok(param_user_id) => param_user_id,
                        Err(e) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't parse path parameter userId: {}", e)))
                                        .expect("Unable to create Bad Request response for invalid path parameter")),
                    },
                    Err(_) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't percent-decode path parameter as UTF-8: {}", &path_params["userId"])))
                                        .expect("Unable to create Bad Request response for invalid percent decode"))
                };

                                let result = api_impl.delete_user(
                                            param_user_id,
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        match result {
                                            Ok(rsp) => match rsp {
                                                DeleteUserResponse::Success
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(202).expect("Unable to turn 202 into a StatusCode");
                                                },
                                                DeleteUserResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");
                                                },
                                                DeleteUserResponse::Forbidden
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(403).expect("Unable to turn 403 into a StatusCode");
                                                },
                                                DeleteUserResponse::NotFound
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(404).expect("Unable to turn 404 into a StatusCode");
                                                },
                                            },
                                            Err(ApiError::NotImplementedError(_)) => {
                                                *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
                                                *response.body_mut() = Body::from(IMPLEMENTATION_NOT_YET_AVAILABLE_ERROR_STRING);
                                            },
                                            // Application code returned an error. This should not happen, as the implementation should return a valid response.
                                            Err(ApiError::UnknownApiError(error_message)) => {
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from(format!("An internal error occurred {}", error_message));
                                            }
                                        }

                                        Ok(response)
            },

            // GetUser - GET /v1/users/{userId}
            hyper::Method::GET if path.matched(paths::ID_V1_USERS_USERID) => {
                {
                    let authorization = match *(&context as &dyn Has<Option<Authorization>>).get() {
                        Some(ref authorization) => authorization,
                        None => return Ok(Response::builder()
                                                .status(StatusCode::FORBIDDEN)
                                                .body(Body::from("Unauthenticated"))
                                                .expect("Unable to create Authentication Forbidden response")),
                    };
                }

                // Path parameters
                let path: &str = uri.path();
                let path_params =
                    paths::REGEX_V1_USERS_USERID
                    .captures(path)
                    .unwrap_or_else(||
                        panic!("Path {} matched RE V1_USERS_USERID in set but failed match against \"{}\"", path, paths::REGEX_V1_USERS_USERID.as_str())
                    );

                let param_user_id = match percent_encoding::percent_decode(path_params["userId"].as_bytes()).decode_utf8() {
                    Ok(param_user_id) => match param_user_id.parse::<String>() {
                        Ok(param_user_id) => param_user_id,
                        Err(e) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't parse path parameter userId: {}", e)))
                                        .expect("Unable to create Bad Request response for invalid path parameter")),
                    },
                    Err(_) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(format!("Couldn't percent-decode path parameter as UTF-8: {}", &path_params["userId"])))
                                        .expect("Unable to create Bad Request response for invalid percent decode"))
                };

                                let result = api_impl.get_user(
                                            param_user_id,
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        match result {
                                            Ok(rsp) => match rsp {
                                                GetUserResponse::Success
                                                    (body)
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(200).expect("Unable to turn 200 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_str("application/links+json")
                                                            .expect("Unable to create Content-Type header for GET_USER_SUCCESS"));
                                                    let body = body;
                                                    *response.body_mut() = Body::from(body);
                                                },
                                                GetUserResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");
                                                },
                                                GetUserResponse::Forbidden
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(403).expect("Unable to turn 403 into a StatusCode");
                                                },
                                                GetUserResponse::NotFound
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(404).expect("Unable to turn 404 into a StatusCode");
                                                },
                                            },
                                            Err(ApiError::NotImplementedError(_)) => {
                                                *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
                                                *response.body_mut() = Body::from(IMPLEMENTATION_NOT_YET_AVAILABLE_ERROR_STRING);
                                            },
                                            // Application code returned an error. This should not happen, as the implementation should return a valid response.
                                            Err(ApiError::UnknownApiError(error_message)) => {
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from(format!("An internal error occurred {}", error_message));
                                            }
                                        }

                                        Ok(response)
            },

            // GetUsers - GET /v1/users
            hyper::Method::GET if path.matched(paths::ID_V1_USERS) => {
                {
                    let authorization = match *(&context as &dyn Has<Option<Authorization>>).get() {
                        Some(ref authorization) => authorization,
                        None => return Ok(Response::builder()
                                                .status(StatusCode::FORBIDDEN)
                                                .body(Body::from("Unauthenticated"))
                                                .expect("Unable to create Authentication Forbidden response")),
                    };
                }

                // Query parameters (note that non-required or collection query parameters will ignore garbage values, rather than causing a 400 response)
                let query_params = form_urlencoded::parse(uri.query().unwrap_or_default().as_bytes()).collect::<Vec<_>>();
                let param_limit = query_params.iter().filter(|e| e.0 == "limit").map(|e| e.1.clone())
                    .next();
                let param_limit = match param_limit {
                    Some(param_limit) => {
                        let param_limit =
                            <i32 as std::str::FromStr>::from_str
                                (&param_limit);
                        match param_limit {
                            Ok(param_limit) => Some(param_limit),
                            Err(e) => return Ok(Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body(Body::from(format!("Couldn't parse query parameter limit - doesn't match schema: {}", e)))
                                .expect("Unable to create Bad Request response for invalid query parameter limit")),
                        }
                    },
                    None => None,
                };
                let param_cursor = query_params.iter().filter(|e| e.0 == "cursor").map(|e| e.1.clone())
                    .next();
                let param_cursor = match param_cursor {
                    Some(param_cursor) => {
                        let param_cursor =
                            <String as std::str::FromStr>::from_str
                                (&param_cursor);
                        match param_cursor {
                            Ok(param_cursor) => Some(param_cursor),
                            Err(e) => return Ok(Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body(Body::from(format!("Couldn't parse query parameter cursor - doesn't match schema: {}", e)))
                                .expect("Unable to create Bad Request response for invalid query parameter cursor")),
                        }
                    },
                    None => None,
                };
                let param_filter = query_params.iter().filter(|e| e.0 == "filter").map(|e| e.1.clone())
                    .next();
                let param_filter = match param_filter {
                    Some(param_filter) => {
                        let param_filter =
                            <String as std::str::FromStr>::from_str
                                (&param_filter);
                        match param_filter {
                            Ok(param_filter) => Some(param_filter),
                            Err(e) => return Ok(Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body(Body::from(format!("Couldn't parse query parameter filter - doesn't match schema: {}", e)))
                                .expect("Unable to create Bad Request response for invalid query parameter filter")),
                        }
                    },
                    None => None,
                };
                let param_tenant_id = query_params.iter().filter(|e| e.0 == "tenantId").map(|e| e.1.clone())
                    .next();
                let param_tenant_id = match param_tenant_id {
                    Some(param_tenant_id) => {
                        let param_tenant_id =
                            <String as std::str::FromStr>::from_str
                                (&param_tenant_id);
                        match param_tenant_id {
                            Ok(param_tenant_id) => Some(param_tenant_id),
                            Err(e) => return Ok(Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body(Body::from(format!("Couldn't parse query parameter tenantId - doesn't match schema: {}", e)))
                                .expect("Unable to create Bad Request response for invalid query parameter tenantId")),
                        }
                    },
                    None => None,
                };

                                let result = api_impl.get_users(
                                            param_limit,
                                            param_cursor,
                                            param_filter,
                                            param_tenant_id,
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        match result {
                                            Ok(rsp) => match rsp {
                                                GetUsersResponse::Success
                                                    (body)
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(200).expect("Unable to turn 200 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_str("application/links+json")
                                                            .expect("Unable to create Content-Type header for GET_USERS_SUCCESS"));
                                                    let body = body;
                                                    *response.body_mut() = Body::from(body);
                                                },
                                                GetUsersResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");
                                                },
                                                GetUsersResponse::Forbidden
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(403).expect("Unable to turn 403 into a StatusCode");
                                                },
                                            },
                                            Err(ApiError::NotImplementedError(_)) => {
                                                *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
                                                *response.body_mut() = Body::from(IMPLEMENTATION_NOT_YET_AVAILABLE_ERROR_STRING);
                                            },
                                            // Application code returned an error. This should not happen, as the implementation should return a valid response.
                                            Err(ApiError::UnknownApiError(error_message)) => {
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from(format!("An internal error occurred {}", error_message));
                                            }
                                        }

                                        Ok(response)
            },

            _ if path.matched(paths::ID_) => method_not_allowed(),
            _ if path.matched(paths::ID_API_AUTHENTICATION_OAUTH_TOKENS) => method_not_allowed(),
            _ if path.matched(paths::ID_V1_ACCOUNTS) => method_not_allowed(),
            _ if path.matched(paths::ID_V1_ACCOUNTS_ACCOUNTID) => method_not_allowed(),
            _ if path.matched(paths::ID_V1_APPLICATIONS_APPLICATIONID_USERS_USERID_DELEGATION) => method_not_allowed(),
            _ if path.matched(paths::ID_V1_CLAIMS) => method_not_allowed(),
            _ if path.matched(paths::ID_V1_CLIENTS) => method_not_allowed(),
            _ if path.matched(paths::ID_V1_CLIENTS_CLIENTID) => method_not_allowed(),
            _ if path.matched(paths::ID_V1_CLIENTS_CLIENTID_ACCESS_KEYS) => method_not_allowed(),
            _ if path.matched(paths::ID_V1_CLIENTS_CLIENTID_ACCESS_KEYS_KEYID) => method_not_allowed(),
            _ if path.matched(paths::ID_V1_CONNECTIONS) => method_not_allowed(),
            _ if path.matched(paths::ID_V1_CONNECTIONS_CONNECTIONID) => method_not_allowed(),
            _ if path.matched(paths::ID_V1_CONNECTIONS_CONNECTIONID_USERS_USERID_CREDENTIALS) => method_not_allowed(),
            _ if path.matched(paths::ID_V1_EXTENSIONS) => method_not_allowed(),
            _ if path.matched(paths::ID_V1_EXTENSIONS_EXTENSIONID) => method_not_allowed(),
            _ if path.matched(paths::ID_V1_GROUPS) => method_not_allowed(),
            _ if path.matched(paths::ID_V1_GROUPS_GROUPID) => method_not_allowed(),
            _ if path.matched(paths::ID_V1_IDENTITIES) => method_not_allowed(),
            _ if path.matched(paths::ID_V1_INVITES) => method_not_allowed(),
            _ if path.matched(paths::ID_V1_INVITES_INVITEID) => method_not_allowed(),
            _ if path.matched(paths::ID_V1_RECORDS) => method_not_allowed(),
            _ if path.matched(paths::ID_V1_RECORDS_RECORDID) => method_not_allowed(),
            _ if path.matched(paths::ID_V1_REQUESTS) => method_not_allowed(),
            _ if path.matched(paths::ID_V1_REQUESTS_REQUESTID) => method_not_allowed(),
            _ if path.matched(paths::ID_V1_RESOURCES) => method_not_allowed(),
            _ if path.matched(paths::ID_V1_RESOURCES_RESOURCEURI) => method_not_allowed(),
            _ if path.matched(paths::ID_V1_RESOURCES_RESOURCEURI_USERS) => method_not_allowed(),
            _ if path.matched(paths::ID_V1_ROLES) => method_not_allowed(),
            _ if path.matched(paths::ID_V1_ROLES_ROLEID) => method_not_allowed(),
            _ if path.matched(paths::ID_V1_TENANTS) => method_not_allowed(),
            _ if path.matched(paths::ID_V1_TENANTS_TENANTID) => method_not_allowed(),
            _ if path.matched(paths::ID_V1_USERS) => method_not_allowed(),
            _ if path.matched(paths::ID_V1_USERS_USERID) => method_not_allowed(),
            _ if path.matched(paths::ID_V1_USERS_USERID_RESOURCES) => method_not_allowed(),
            _ if path.matched(paths::ID_V1_USERS_USERID_RESOURCES_RESOURCEURI_PERMISSIONS) => method_not_allowed(),
            _ if path.matched(paths::ID_V1_USERS_USERID_RESOURCES_RESOURCEURI_PERMISSIONS_PERMISSION) => method_not_allowed(),
            _ if path.matched(paths::ID_V1_USERS_USERID_RESOURCES_RESOURCEURI_ROLES) => method_not_allowed(),
            _ => Ok(Response::builder().status(StatusCode::NOT_FOUND)
                    .body(Body::empty())
                    .expect("Unable to create Not Found response"))
        }
    } Box::pin(run(self.api_impl.clone(), req)) }
}

/// Request parser for `Api`.
pub struct ApiRequestParser;
impl<T> RequestParser<T> for ApiRequestParser {
    fn parse_operation_id(request: &Request<T>) -> Option<&'static str> {
        let path = paths::GLOBAL_REGEX_SET.matches(request.uri().path());
        match *request.method() {
            // CreateClaim - POST /v1/claims
            hyper::Method::POST if path.matched(paths::ID_V1_CLAIMS) => Some("CreateClaim"),
            // CreateInvite - POST /v1/invites
            hyper::Method::POST if path.matched(paths::ID_V1_INVITES) => Some("CreateInvite"),
            // CreateRecord - POST /v1/records
            hyper::Method::POST if path.matched(paths::ID_V1_RECORDS) => Some("CreateRecord"),
            // CreateRequest - POST /v1/requests
            hyper::Method::POST if path.matched(paths::ID_V1_REQUESTS) => Some("CreateRequest"),
            // DeleteInvite - DELETE /v1/invites/{inviteId}
            hyper::Method::DELETE if path.matched(paths::ID_V1_INVITES_INVITEID) => Some("DeleteInvite"),
            // DeleteRecord - DELETE /v1/records/{recordId}
            hyper::Method::DELETE if path.matched(paths::ID_V1_RECORDS_RECORDID) => Some("DeleteRecord"),
            // DeleteRequest - DELETE /v1/requests/{requestId}
            hyper::Method::DELETE if path.matched(paths::ID_V1_REQUESTS_REQUESTID) => Some("DeleteRequest"),
            // GetRecord - GET /v1/records/{recordId}
            hyper::Method::GET if path.matched(paths::ID_V1_RECORDS_RECORDID) => Some("GetRecord"),
            // GetRecords - GET /v1/records
            hyper::Method::GET if path.matched(paths::ID_V1_RECORDS) => Some("GetRecords"),
            // GetRequest - GET /v1/requests/{requestId}
            hyper::Method::GET if path.matched(paths::ID_V1_REQUESTS_REQUESTID) => Some("GetRequest"),
            // GetRequests - GET /v1/requests
            hyper::Method::GET if path.matched(paths::ID_V1_REQUESTS) => Some("GetRequests"),
            // RespondToAccessRequest - PATCH /v1/requests/{requestId}
            hyper::Method::PATCH if path.matched(paths::ID_V1_REQUESTS_REQUESTID) => Some("RespondToAccessRequest"),
            // RespondToInvite - PATCH /v1/invites/{inviteId}
            hyper::Method::PATCH if path.matched(paths::ID_V1_INVITES_INVITEID) => Some("RespondToInvite"),
            // UpdateRecord - PUT /v1/records/{recordId}
            hyper::Method::PUT if path.matched(paths::ID_V1_RECORDS_RECORDID) => Some("UpdateRecord"),
            // DelegateAuthentication - POST /v1/identities
            hyper::Method::POST if path.matched(paths::ID_V1_IDENTITIES) => Some("DelegateAuthentication"),
            // GetAccount - GET /v1/accounts/{accountId}
            hyper::Method::GET if path.matched(paths::ID_V1_ACCOUNTS_ACCOUNTID) => Some("GetAccount"),
            // GetAccountIdentities - GET /v1/identities
            hyper::Method::GET if path.matched(paths::ID_V1_IDENTITIES) => Some("GetAccountIdentities"),
            // GetAccounts - GET /v1/accounts
            hyper::Method::GET if path.matched(paths::ID_V1_ACCOUNTS) => Some("GetAccounts"),
            // DelegateUserLogin - POST /v1/applications/{applicationId}/users/{userId}/delegation
            hyper::Method::POST if path.matched(paths::ID_V1_APPLICATIONS_APPLICATIONID_USERS_USERID_DELEGATION) => Some("DelegateUserLogin"),
            // CreateConnection - POST /v1/connections
            hyper::Method::POST if path.matched(paths::ID_V1_CONNECTIONS) => Some("CreateConnection"),
            // DeleteConnection - DELETE /v1/connections/{connectionId}
            hyper::Method::DELETE if path.matched(paths::ID_V1_CONNECTIONS_CONNECTIONID) => Some("DeleteConnection"),
            // GetConnection - GET /v1/connections/{connectionId}
            hyper::Method::GET if path.matched(paths::ID_V1_CONNECTIONS_CONNECTIONID) => Some("GetConnection"),
            // GetConnectionCredentials - GET /v1/connections/{connectionId}/users/{userId}/credentials
            hyper::Method::GET if path.matched(paths::ID_V1_CONNECTIONS_CONNECTIONID_USERS_USERID_CREDENTIALS) => Some("GetConnectionCredentials"),
            // GetConnections - GET /v1/connections
            hyper::Method::GET if path.matched(paths::ID_V1_CONNECTIONS) => Some("GetConnections"),
            // UpdateConnection - PUT /v1/connections/{connectionId}
            hyper::Method::PUT if path.matched(paths::ID_V1_CONNECTIONS_CONNECTIONID) => Some("UpdateConnection"),
            // CreateExtension - POST /v1/extensions
            hyper::Method::POST if path.matched(paths::ID_V1_EXTENSIONS) => Some("CreateExtension"),
            // DeleteExtension - DELETE /v1/extensions/{extensionId}
            hyper::Method::DELETE if path.matched(paths::ID_V1_EXTENSIONS_EXTENSIONID) => Some("DeleteExtension"),
            // GetExtension - GET /v1/extensions/{extensionId}
            hyper::Method::GET if path.matched(paths::ID_V1_EXTENSIONS_EXTENSIONID) => Some("GetExtension"),
            // GetExtensions - GET /v1/extensions
            hyper::Method::GET if path.matched(paths::ID_V1_EXTENSIONS) => Some("GetExtensions"),
            // Login - GET /
            hyper::Method::GET if path.matched(paths::ID_) => Some("Login"),
            // RequestToken - POST /api/authentication/oauth/tokens
            hyper::Method::POST if path.matched(paths::ID_API_AUTHENTICATION_OAUTH_TOKENS) => Some("RequestToken"),
            // UpdateExtension - PUT /v1/extensions/{extensionId}
            hyper::Method::PUT if path.matched(paths::ID_V1_EXTENSIONS_EXTENSIONID) => Some("UpdateExtension"),
            // CreateGroup - POST /v1/groups
            hyper::Method::POST if path.matched(paths::ID_V1_GROUPS) => Some("CreateGroup"),
            // DeleteGroup - DELETE /v1/groups/{groupId}
            hyper::Method::DELETE if path.matched(paths::ID_V1_GROUPS_GROUPID) => Some("DeleteGroup"),
            // GetGroup - GET /v1/groups/{groupId}
            hyper::Method::GET if path.matched(paths::ID_V1_GROUPS_GROUPID) => Some("GetGroup"),
            // GetGroups - GET /v1/groups
            hyper::Method::GET if path.matched(paths::ID_V1_GROUPS) => Some("GetGroups"),
            // UpdateGroup - PUT /v1/groups/{groupId}
            hyper::Method::PUT if path.matched(paths::ID_V1_GROUPS_GROUPID) => Some("UpdateGroup"),
            // GetPermissionedResource - GET /v1/resources/{resourceUri}
            hyper::Method::GET if path.matched(paths::ID_V1_RESOURCES_RESOURCEURI) => Some("GetPermissionedResource"),
            // GetPermissionedResources - GET /v1/resources
            hyper::Method::GET if path.matched(paths::ID_V1_RESOURCES) => Some("GetPermissionedResources"),
            // GetResourceUsers - GET /v1/resources/{resourceUri}/users
            hyper::Method::GET if path.matched(paths::ID_V1_RESOURCES_RESOURCEURI_USERS) => Some("GetResourceUsers"),
            // UpdatePermissionedResource - PUT /v1/resources/{resourceUri}
            hyper::Method::PUT if path.matched(paths::ID_V1_RESOURCES_RESOURCEURI) => Some("UpdatePermissionedResource"),
            // CreateRole - POST /v1/roles
            hyper::Method::POST if path.matched(paths::ID_V1_ROLES) => Some("CreateRole"),
            // DeleteRole - DELETE /v1/roles/{roleId}
            hyper::Method::DELETE if path.matched(paths::ID_V1_ROLES_ROLEID) => Some("DeleteRole"),
            // GetRole - GET /v1/roles/{roleId}
            hyper::Method::GET if path.matched(paths::ID_V1_ROLES_ROLEID) => Some("GetRole"),
            // GetRoles - GET /v1/roles
            hyper::Method::GET if path.matched(paths::ID_V1_ROLES) => Some("GetRoles"),
            // UpdateRole - PUT /v1/roles/{roleId}
            hyper::Method::PUT if path.matched(paths::ID_V1_ROLES_ROLEID) => Some("UpdateRole"),
            // CreateClient - POST /v1/clients
            hyper::Method::POST if path.matched(paths::ID_V1_CLIENTS) => Some("CreateClient"),
            // DeleteAccessKey - DELETE /v1/clients/{clientId}/access-keys/{keyId}
            hyper::Method::DELETE if path.matched(paths::ID_V1_CLIENTS_CLIENTID_ACCESS_KEYS_KEYID) => Some("DeleteAccessKey"),
            // DeleteClient - DELETE /v1/clients/{clientId}
            hyper::Method::DELETE if path.matched(paths::ID_V1_CLIENTS_CLIENTID) => Some("DeleteClient"),
            // GetClient - GET /v1/clients/{clientId}
            hyper::Method::GET if path.matched(paths::ID_V1_CLIENTS_CLIENTID) => Some("GetClient"),
            // GetClients - GET /v1/clients
            hyper::Method::GET if path.matched(paths::ID_V1_CLIENTS) => Some("GetClients"),
            // RequestAccessKey - POST /v1/clients/{clientId}/access-keys
            hyper::Method::POST if path.matched(paths::ID_V1_CLIENTS_CLIENTID_ACCESS_KEYS) => Some("RequestAccessKey"),
            // UpdateClient - PUT /v1/clients/{clientId}
            hyper::Method::PUT if path.matched(paths::ID_V1_CLIENTS_CLIENTID) => Some("UpdateClient"),
            // CreateTenant - POST /v1/tenants
            hyper::Method::POST if path.matched(paths::ID_V1_TENANTS) => Some("CreateTenant"),
            // DeleteTenant - DELETE /v1/tenants/{tenantId}
            hyper::Method::DELETE if path.matched(paths::ID_V1_TENANTS_TENANTID) => Some("DeleteTenant"),
            // GetTenant - GET /v1/tenants/{tenantId}
            hyper::Method::GET if path.matched(paths::ID_V1_TENANTS_TENANTID) => Some("GetTenant"),
            // GetTenants - GET /v1/tenants
            hyper::Method::GET if path.matched(paths::ID_V1_TENANTS) => Some("GetTenants"),
            // UpdateTenant - PUT /v1/tenants/{tenantId}
            hyper::Method::PUT if path.matched(paths::ID_V1_TENANTS_TENANTID) => Some("UpdateTenant"),
            // AuthorizeUser - GET /v1/users/{userId}/resources/{resourceUri}/permissions/{permission}
            hyper::Method::GET if path.matched(paths::ID_V1_USERS_USERID_RESOURCES_RESOURCEURI_PERMISSIONS_PERMISSION) => Some("AuthorizeUser"),
            // GetUserPermissionsForResource - GET /v1/users/{userId}/resources/{resourceUri}/permissions
            hyper::Method::GET if path.matched(paths::ID_V1_USERS_USERID_RESOURCES_RESOURCEURI_PERMISSIONS) => Some("GetUserPermissionsForResource"),
            // GetUserResources - GET /v1/users/{userId}/resources
            hyper::Method::GET if path.matched(paths::ID_V1_USERS_USERID_RESOURCES) => Some("GetUserResources"),
            // GetUserRolesForResource - GET /v1/users/{userId}/resources/{resourceUri}/roles
            hyper::Method::GET if path.matched(paths::ID_V1_USERS_USERID_RESOURCES_RESOURCEURI_ROLES) => Some("GetUserRolesForResource"),
            // DeleteUser - DELETE /v1/users/{userId}
            hyper::Method::DELETE if path.matched(paths::ID_V1_USERS_USERID) => Some("DeleteUser"),
            // GetUser - GET /v1/users/{userId}
            hyper::Method::GET if path.matched(paths::ID_V1_USERS_USERID) => Some("GetUser"),
            // GetUsers - GET /v1/users
            hyper::Method::GET if path.matched(paths::ID_V1_USERS) => Some("GetUsers"),
            _ => None,
        }
    }
}

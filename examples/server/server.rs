//! Main library entry point for authress_local implementation.

#![allow(unused_imports)]

use async_trait::async_trait;
use futures::{future, Stream, StreamExt, TryFutureExt, TryStreamExt};
use hyper::server::conn::Http;
use hyper::service::Service;
use log::info;
use std::future::Future;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use swagger::{Has, XSpanIdString};
use swagger::auth::MakeAllowAllAuthenticator;
use swagger::EmptyContext;
use tokio::net::TcpListener;

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "ios")))]
use openssl::ssl::{Ssl, SslAcceptor, SslAcceptorBuilder, SslFiletype, SslMethod};

use authress::models;

/// Builds an SSL implementation for Simple HTTPS from some hard-coded file names
pub async fn create(addr: &str, https: bool) {
    let addr = addr.parse().expect("Failed to parse bind address");

    let server = Server::new();

    let service = MakeService::new(server);

    let service = MakeAllowAllAuthenticator::new(service, "cosmo");

    #[allow(unused_mut)]
    let mut service =
        authress_local::server::context::MakeAddContext::<_, EmptyContext>::new(
            service
        );

    if https {
        #[cfg(any(target_os = "macos", target_os = "windows", target_os = "ios"))]
        {
            unimplemented!("SSL is not implemented for the examples on MacOS, Windows or iOS");
        }

        #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "ios")))]
        {
            let mut ssl = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).expect("Failed to create SSL Acceptor");

            // Server authentication
            ssl.set_private_key_file("examples/server-key.pem", SslFiletype::PEM).expect("Failed to set private key");
            ssl.set_certificate_chain_file("examples/server-chain.pem").expect("Failed to set certificate chain");
            ssl.check_private_key().expect("Failed to check private key");

            let tls_acceptor = ssl.build();
            let tcp_listener = TcpListener::bind(&addr).await.unwrap();

            loop {
                if let Ok((tcp, _)) = tcp_listener.accept().await {
                    let ssl = Ssl::new(tls_acceptor.context()).unwrap();
                    let addr = tcp.peer_addr().expect("Unable to get remote address");
                    let service = service.call(addr);

                    tokio::spawn(async move {
                        let tls = tokio_openssl::SslStream::new(ssl, tcp).map_err(|_| ())?;
                        let service = service.await.map_err(|_| ())?;

                        Http::new()
                            .serve_connection(tls, service)
                            .await
                            .map_err(|_| ())
                    });
                }
            }
        }
    } else {
        // Using HTTP
        hyper::server::Server::bind(&addr).serve(service).await.unwrap()
    }
}

#[derive(Copy, Clone)]
pub struct Server<C> {
    marker: PhantomData<C>,
}

impl<C> Server<C> {
    pub fn new() -> Self {
        Server{marker: PhantomData}
    }
}


use authress_local::{
    Api,
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
    GetUsersResponse,
};
use authress_local::server::MakeService;
use std::error::Error;
use swagger::ApiError;

#[async_trait]
impl<C> Api<C> for Server<C> where C: Has<XSpanIdString> + Send + Sync
{
    /// Create resource Claim
    async fn create_claim(
        &self,
        claim_request: models::ClaimRequest,
        context: &C) -> Result<CreateClaimResponse, ApiError>
    {
        let context = context.clone();
        info!("create_claim({:?}) - X-Span-ID: {:?}", claim_request, context.get().0.clone());
        Err(ApiError("Generic failure".into()))
    }

    /// Create user invite
    async fn create_invite(
        &self,
        invite: models::Invite,
        context: &C) -> Result<CreateInviteResponse, ApiError>
    {
        let context = context.clone();
        info!("create_invite({:?}) - X-Span-ID: {:?}", invite, context.get().0.clone());
        Err(ApiError("Generic failure".into()))
    }

    /// Create access record
    async fn create_record(
        &self,
        access_record: models::AccessRecord,
        context: &C) -> Result<CreateRecordResponse, ApiError>
    {
        let context = context.clone();
        info!("create_record({:?}) - X-Span-ID: {:?}", access_record, context.get().0.clone());
        Err(ApiError("Generic failure".into()))
    }

    /// Create access request
    async fn create_request(
        &self,
        access_request: models::AccessRequest,
        context: &C) -> Result<CreateRequestResponse, ApiError>
    {
        let context = context.clone();
        info!("create_request({:?}) - X-Span-ID: {:?}", access_request, context.get().0.clone());
        Err(ApiError("Generic failure".into()))
    }

    /// Delete invite
    async fn delete_invite(
        &self,
        invite_id: String,
        context: &C) -> Result<DeleteInviteResponse, ApiError>
    {
        let context = context.clone();
        info!("delete_invite(\"{}\") - X-Span-ID: {:?}", invite_id, context.get().0.clone());
        Err(ApiError("Generic failure".into()))
    }

    /// Deletes access record
    async fn delete_record(
        &self,
        record_id: String,
        context: &C) -> Result<DeleteRecordResponse, ApiError>
    {
        let context = context.clone();
        info!("delete_record(\"{}\") - X-Span-ID: {:?}", record_id, context.get().0.clone());
        Err(ApiError("Generic failure".into()))
    }

    /// Deletes access request
    async fn delete_request(
        &self,
        request_id: String,
        context: &C) -> Result<DeleteRequestResponse, ApiError>
    {
        let context = context.clone();
        info!("delete_request(\"{}\") - X-Span-ID: {:?}", request_id, context.get().0.clone());
        Err(ApiError("Generic failure".into()))
    }

    /// Retrieve access record
    async fn get_record(
        &self,
        record_id: String,
        context: &C) -> Result<GetRecordResponse, ApiError>
    {
        let context = context.clone();
        info!("get_record(\"{}\") - X-Span-ID: {:?}", record_id, context.get().0.clone());
        Err(ApiError("Generic failure".into()))
    }

    /// List access records
    async fn get_records(
        &self,
        limit: Option<i32>,
        cursor: Option<String>,
        filter: Option<String>,
        status: Option<String>,
        context: &C) -> Result<GetRecordsResponse, ApiError>
    {
        let context = context.clone();
        info!("get_records({:?}, {:?}, {:?}, {:?}) - X-Span-ID: {:?}", limit, cursor, filter, status, context.get().0.clone());
        Err(ApiError("Generic failure".into()))
    }

    /// Retrieve access request
    async fn get_request(
        &self,
        request_id: String,
        context: &C) -> Result<GetRequestResponse, ApiError>
    {
        let context = context.clone();
        info!("get_request(\"{}\") - X-Span-ID: {:?}", request_id, context.get().0.clone());
        Err(ApiError("Generic failure".into()))
    }

    /// List access requests
    async fn get_requests(
        &self,
        limit: Option<i32>,
        cursor: Option<String>,
        status: Option<String>,
        context: &C) -> Result<GetRequestsResponse, ApiError>
    {
        let context = context.clone();
        info!("get_requests({:?}, {:?}, {:?}) - X-Span-ID: {:?}", limit, cursor, status, context.get().0.clone());
        Err(ApiError("Generic failure".into()))
    }

    /// Approve or deny access request
    async fn respond_to_access_request(
        &self,
        request_id: String,
        access_request_response: models::AccessRequestResponse,
        context: &C) -> Result<RespondToAccessRequestResponse, ApiError>
    {
        let context = context.clone();
        info!("respond_to_access_request(\"{}\", {:?}) - X-Span-ID: {:?}", request_id, access_request_response, context.get().0.clone());
        Err(ApiError("Generic failure".into()))
    }

    /// Accept invite
    async fn respond_to_invite(
        &self,
        invite_id: String,
        context: &C) -> Result<RespondToInviteResponse, ApiError>
    {
        let context = context.clone();
        info!("respond_to_invite(\"{}\") - X-Span-ID: {:?}", invite_id, context.get().0.clone());
        Err(ApiError("Generic failure".into()))
    }

    /// Update access record
    async fn update_record(
        &self,
        record_id: String,
        access_record: models::AccessRecord,
        if_unmodified_since: Option<String>,
        context: &C) -> Result<UpdateRecordResponse, ApiError>
    {
        let context = context.clone();
        info!("update_record(\"{}\", {:?}, {:?}) - X-Span-ID: {:?}", record_id, access_record, if_unmodified_since, context.get().0.clone());
        Err(ApiError("Generic failure".into()))
    }

    /// Link external provider
    async fn delegate_authentication(
        &self,
        identity_request: models::IdentityRequest,
        context: &C) -> Result<DelegateAuthenticationResponse, ApiError>
    {
        let context = context.clone();
        info!("delegate_authentication({:?}) - X-Span-ID: {:?}", identity_request, context.get().0.clone());
        Err(ApiError("Generic failure".into()))
    }

    /// Retrieve account information
    async fn get_account(
        &self,
        account_id: String,
        context: &C) -> Result<GetAccountResponse, ApiError>
    {
        let context = context.clone();
        info!("get_account(\"{}\") - X-Span-ID: {:?}", account_id, context.get().0.clone());
        Err(ApiError("Generic failure".into()))
    }

    /// List linked external providers
    async fn get_account_identities(
        &self,
        context: &C) -> Result<GetAccountIdentitiesResponse, ApiError>
    {
        let context = context.clone();
        info!("get_account_identities() - X-Span-ID: {:?}", context.get().0.clone());
        Err(ApiError("Generic failure".into()))
    }

    /// List user Authress accounts
    async fn get_accounts(
        &self,
        earliest_cache_time: Option<chrono::DateTime::<chrono::Utc>>,
        context: &C) -> Result<GetAccountsResponse, ApiError>
    {
        let context = context.clone();
        info!("get_accounts({:?}) - X-Span-ID: {:?}", earliest_cache_time, context.get().0.clone());
        Err(ApiError("Generic failure".into()))
    }

    /// Log user into third-party application
    async fn delegate_user_login(
        &self,
        application_id: String,
        user_id: String,
        context: &C) -> Result<DelegateUserLoginResponse, ApiError>
    {
        let context = context.clone();
        info!("delegate_user_login(\"{}\", {:?}) - X-Span-ID: {:?}", application_id, user_id, context.get().0.clone());
        Err(ApiError("Generic failure".into()))
    }

    /// Create SSO connection
    async fn create_connection(
        &self,
        connection: models::Connection,
        context: &C) -> Result<CreateConnectionResponse, ApiError>
    {
        let context = context.clone();
        info!("create_connection({:?}) - X-Span-ID: {:?}", connection, context.get().0.clone());
        Err(ApiError("Generic failure".into()))
    }

    /// Delete SSO connection
    async fn delete_connection(
        &self,
        connection_id: String,
        context: &C) -> Result<DeleteConnectionResponse, ApiError>
    {
        let context = context.clone();
        info!("delete_connection(\"{}\") - X-Span-ID: {:?}", connection_id, context.get().0.clone());
        Err(ApiError("Generic failure".into()))
    }

    /// Retrieve SSO connection
    async fn get_connection(
        &self,
        connection_id: String,
        context: &C) -> Result<GetConnectionResponse, ApiError>
    {
        let context = context.clone();
        info!("get_connection(\"{}\") - X-Span-ID: {:?}", connection_id, context.get().0.clone());
        Err(ApiError("Generic failure".into()))
    }

    /// Retrieve user connection credentials
    async fn get_connection_credentials(
        &self,
        connection_id: String,
        user_id: String,
        context: &C) -> Result<GetConnectionCredentialsResponse, ApiError>
    {
        let context = context.clone();
        info!("get_connection_credentials(\"{}\", {:?}) - X-Span-ID: {:?}", connection_id, user_id, context.get().0.clone());
        Err(ApiError("Generic failure".into()))
    }

    /// List SSO connections
    async fn get_connections(
        &self,
        context: &C) -> Result<GetConnectionsResponse, ApiError>
    {
        let context = context.clone();
        info!("get_connections() - X-Span-ID: {:?}", context.get().0.clone());
        Err(ApiError("Generic failure".into()))
    }

    /// Update SSO connection
    async fn update_connection(
        &self,
        connection_id: String,
        connection: models::Connection,
        context: &C) -> Result<UpdateConnectionResponse, ApiError>
    {
        let context = context.clone();
        info!("update_connection(\"{}\", {:?}) - X-Span-ID: {:?}", connection_id, connection, context.get().0.clone());
        Err(ApiError("Generic failure".into()))
    }

    /// Create extension
    async fn create_extension(
        &self,
        extension: models::Extension,
        context: &C) -> Result<CreateExtensionResponse, ApiError>
    {
        let context = context.clone();
        info!("create_extension({:?}) - X-Span-ID: {:?}", extension, context.get().0.clone());
        Err(ApiError("Generic failure".into()))
    }

    /// Delete extension
    async fn delete_extension(
        &self,
        extension_id: String,
        context: &C) -> Result<DeleteExtensionResponse, ApiError>
    {
        let context = context.clone();
        info!("delete_extension(\"{}\") - X-Span-ID: {:?}", extension_id, context.get().0.clone());
        Err(ApiError("Generic failure".into()))
    }

    /// Retrieve extension
    async fn get_extension(
        &self,
        extension_id: String,
        context: &C) -> Result<GetExtensionResponse, ApiError>
    {
        let context = context.clone();
        info!("get_extension(\"{}\") - X-Span-ID: {:?}", extension_id, context.get().0.clone());
        Err(ApiError("Generic failure".into()))
    }

    /// List extensions
    async fn get_extensions(
        &self,
        context: &C) -> Result<GetExtensionsResponse, ApiError>
    {
        let context = context.clone();
        info!("get_extensions() - X-Span-ID: {:?}", context.get().0.clone());
        Err(ApiError("Generic failure".into()))
    }

    /// OAuth Authorize
    async fn login(
        &self,
        client_id: String,
        code_challenge: String,
        redirect_uri: String,
        code_challenge_method: Option<String>,
        context: &C) -> Result<LoginResponse, ApiError>
    {
        let context = context.clone();
        info!("login(\"{}\", \"{}\", \"{}\", {:?}) - X-Span-ID: {:?}", client_id, code_challenge, redirect_uri, code_challenge_method, context.get().0.clone());
        Err(ApiError("Generic failure".into()))
    }

    /// OAuth Token
    async fn request_token(
        &self,
        o_auth_token_request: models::OAuthTokenRequest,
        context: &C) -> Result<RequestTokenResponse, ApiError>
    {
        let context = context.clone();
        info!("request_token({:?}) - X-Span-ID: {:?}", o_auth_token_request, context.get().0.clone());
        Err(ApiError("Generic failure".into()))
    }

    /// Update extension
    async fn update_extension(
        &self,
        extension_id: String,
        extension: models::Extension,
        context: &C) -> Result<UpdateExtensionResponse, ApiError>
    {
        let context = context.clone();
        info!("update_extension(\"{}\", {:?}) - X-Span-ID: {:?}", extension_id, extension, context.get().0.clone());
        Err(ApiError("Generic failure".into()))
    }

    /// Create group
    async fn create_group(
        &self,
        group: models::Group,
        context: &C) -> Result<CreateGroupResponse, ApiError>
    {
        let context = context.clone();
        info!("create_group({:?}) - X-Span-ID: {:?}", group, context.get().0.clone());
        Err(ApiError("Generic failure".into()))
    }

    /// Deletes group
    async fn delete_group(
        &self,
        group_id: String,
        context: &C) -> Result<DeleteGroupResponse, ApiError>
    {
        let context = context.clone();
        info!("delete_group({:?}) - X-Span-ID: {:?}", group_id, context.get().0.clone());
        Err(ApiError("Generic failure".into()))
    }

    /// Retrieve group
    async fn get_group(
        &self,
        group_id: String,
        context: &C) -> Result<GetGroupResponse, ApiError>
    {
        let context = context.clone();
        info!("get_group({:?}) - X-Span-ID: {:?}", group_id, context.get().0.clone());
        Err(ApiError("Generic failure".into()))
    }

    /// List groups
    async fn get_groups(
        &self,
        limit: Option<i32>,
        cursor: Option<String>,
        filter: Option<String>,
        context: &C) -> Result<GetGroupsResponse, ApiError>
    {
        let context = context.clone();
        info!("get_groups({:?}, {:?}, {:?}) - X-Span-ID: {:?}", limit, cursor, filter, context.get().0.clone());
        Err(ApiError("Generic failure".into()))
    }

    /// Update a group
    async fn update_group(
        &self,
        group_id: String,
        group: models::Group,
        context: &C) -> Result<UpdateGroupResponse, ApiError>
    {
        let context = context.clone();
        info!("update_group({:?}, {:?}) - X-Span-ID: {:?}", group_id, group, context.get().0.clone());
        Err(ApiError("Generic failure".into()))
    }

    /// Retrieve resource configuration
    async fn get_permissioned_resource(
        &self,
        resource_uri: String,
        context: &C) -> Result<GetPermissionedResourceResponse, ApiError>
    {
        let context = context.clone();
        info!("get_permissioned_resource(\"{}\") - X-Span-ID: {:?}", resource_uri, context.get().0.clone());
        Err(ApiError("Generic failure".into()))
    }

    /// List all resource configurations
    async fn get_permissioned_resources(
        &self,
        context: &C) -> Result<GetPermissionedResourcesResponse, ApiError>
    {
        let context = context.clone();
        info!("get_permissioned_resources() - X-Span-ID: {:?}", context.get().0.clone());
        Err(ApiError("Generic failure".into()))
    }

    /// List users with resource access
    async fn get_resource_users(
        &self,
        resource_uri: String,
        limit: Option<i32>,
        cursor: Option<String>,
        context: &C) -> Result<GetResourceUsersResponse, ApiError>
    {
        let context = context.clone();
        info!("get_resource_users(\"{}\", {:?}, {:?}) - X-Span-ID: {:?}", resource_uri, limit, cursor, context.get().0.clone());
        Err(ApiError("Generic failure".into()))
    }

    /// Update resource configuration
    async fn update_permissioned_resource(
        &self,
        resource_uri: String,
        permissioned_resource: models::PermissionedResource,
        context: &C) -> Result<UpdatePermissionedResourceResponse, ApiError>
    {
        let context = context.clone();
        info!("update_permissioned_resource(\"{}\", {:?}) - X-Span-ID: {:?}", resource_uri, permissioned_resource, context.get().0.clone());
        Err(ApiError("Generic failure".into()))
    }

    /// Create role
    async fn create_role(
        &self,
        role: models::Role,
        context: &C) -> Result<CreateRoleResponse, ApiError>
    {
        let context = context.clone();
        info!("create_role({:?}) - X-Span-ID: {:?}", role, context.get().0.clone());
        Err(ApiError("Generic failure".into()))
    }

    /// Deletes role
    async fn delete_role(
        &self,
        role_id: String,
        context: &C) -> Result<DeleteRoleResponse, ApiError>
    {
        let context = context.clone();
        info!("delete_role(\"{}\") - X-Span-ID: {:?}", role_id, context.get().0.clone());
        Err(ApiError("Generic failure".into()))
    }

    /// Retrieve role
    async fn get_role(
        &self,
        role_id: String,
        context: &C) -> Result<GetRoleResponse, ApiError>
    {
        let context = context.clone();
        info!("get_role(\"{}\") - X-Span-ID: {:?}", role_id, context.get().0.clone());
        Err(ApiError("Generic failure".into()))
    }

    /// List roles
    async fn get_roles(
        &self,
        context: &C) -> Result<GetRolesResponse, ApiError>
    {
        let context = context.clone();
        info!("get_roles() - X-Span-ID: {:?}", context.get().0.clone());
        Err(ApiError("Generic failure".into()))
    }

    /// Update role
    async fn update_role(
        &self,
        role_id: String,
        role: models::Role,
        context: &C) -> Result<UpdateRoleResponse, ApiError>
    {
        let context = context.clone();
        info!("update_role(\"{}\", {:?}) - X-Span-ID: {:?}", role_id, role, context.get().0.clone());
        Err(ApiError("Generic failure".into()))
    }

    /// Create service client
    async fn create_client(
        &self,
        client: models::Client,
        context: &C) -> Result<CreateClientResponse, ApiError>
    {
        let context = context.clone();
        info!("create_client({:?}) - X-Span-ID: {:?}", client, context.get().0.clone());
        Err(ApiError("Generic failure".into()))
    }

    /// Delete service client access key
    async fn delete_access_key(
        &self,
        client_id: String,
        key_id: String,
        context: &C) -> Result<DeleteAccessKeyResponse, ApiError>
    {
        let context = context.clone();
        info!("delete_access_key(\"{}\", \"{}\") - X-Span-ID: {:?}", client_id, key_id, context.get().0.clone());
        Err(ApiError("Generic failure".into()))
    }

    /// Delete service client
    async fn delete_client(
        &self,
        client_id: String,
        context: &C) -> Result<DeleteClientResponse, ApiError>
    {
        let context = context.clone();
        info!("delete_client(\"{}\") - X-Span-ID: {:?}", client_id, context.get().0.clone());
        Err(ApiError("Generic failure".into()))
    }

    /// Retrieve service client
    async fn get_client(
        &self,
        client_id: String,
        context: &C) -> Result<GetClientResponse, ApiError>
    {
        let context = context.clone();
        info!("get_client(\"{}\") - X-Span-ID: {:?}", client_id, context.get().0.clone());
        Err(ApiError("Generic failure".into()))
    }

    /// List service clients
    async fn get_clients(
        &self,
        limit: Option<i32>,
        cursor: Option<String>,
        context: &C) -> Result<GetClientsResponse, ApiError>
    {
        let context = context.clone();
        info!("get_clients({:?}, {:?}) - X-Span-ID: {:?}", limit, cursor, context.get().0.clone());
        Err(ApiError("Generic failure".into()))
    }

    /// Generate service client access key
    async fn request_access_key(
        &self,
        client_id: String,
        context: &C) -> Result<RequestAccessKeyResponse, ApiError>
    {
        let context = context.clone();
        info!("request_access_key(\"{}\") - X-Span-ID: {:?}", client_id, context.get().0.clone());
        Err(ApiError("Generic failure".into()))
    }

    /// Update service client
    async fn update_client(
        &self,
        client_id: String,
        client: models::Client,
        context: &C) -> Result<UpdateClientResponse, ApiError>
    {
        let context = context.clone();
        info!("update_client(\"{}\", {:?}) - X-Span-ID: {:?}", client_id, client, context.get().0.clone());
        Err(ApiError("Generic failure".into()))
    }

    /// Create tenant
    async fn create_tenant(
        &self,
        tenant: models::Tenant,
        context: &C) -> Result<CreateTenantResponse, ApiError>
    {
        let context = context.clone();
        info!("create_tenant({:?}) - X-Span-ID: {:?}", tenant, context.get().0.clone());
        Err(ApiError("Generic failure".into()))
    }

    /// Delete tenant
    async fn delete_tenant(
        &self,
        tenant_id: String,
        context: &C) -> Result<DeleteTenantResponse, ApiError>
    {
        let context = context.clone();
        info!("delete_tenant(\"{}\") - X-Span-ID: {:?}", tenant_id, context.get().0.clone());
        Err(ApiError("Generic failure".into()))
    }

    /// Retrieve tenant
    async fn get_tenant(
        &self,
        tenant_id: String,
        context: &C) -> Result<GetTenantResponse, ApiError>
    {
        let context = context.clone();
        info!("get_tenant(\"{}\") - X-Span-ID: {:?}", tenant_id, context.get().0.clone());
        Err(ApiError("Generic failure".into()))
    }

    /// List tenants
    async fn get_tenants(
        &self,
        context: &C) -> Result<GetTenantsResponse, ApiError>
    {
        let context = context.clone();
        info!("get_tenants() - X-Span-ID: {:?}", context.get().0.clone());
        Err(ApiError("Generic failure".into()))
    }

    /// Update tenant
    async fn update_tenant(
        &self,
        tenant_id: String,
        tenant: models::Tenant,
        context: &C) -> Result<UpdateTenantResponse, ApiError>
    {
        let context = context.clone();
        info!("update_tenant(\"{}\", {:?}) - X-Span-ID: {:?}", tenant_id, tenant, context.get().0.clone());
        Err(ApiError("Generic failure".into()))
    }

    /// Verify user authorization
    async fn authorize_user(
        &self,
        user_id: String,
        resource_uri: String,
        permission: String,
        context: &C) -> Result<AuthorizeUserResponse, ApiError>
    {
        let context = context.clone();
        info!("authorize_user({:?}, \"{}\", {:?}) - X-Span-ID: {:?}", user_id, resource_uri, permission, context.get().0.clone());
        Err(ApiError("Generic failure".into()))
    }

    /// Get user permissions for resource
    async fn get_user_permissions_for_resource(
        &self,
        user_id: String,
        resource_uri: String,
        context: &C) -> Result<GetUserPermissionsForResourceResponse, ApiError>
    {
        let context = context.clone();
        info!("get_user_permissions_for_resource({:?}, \"{}\") - X-Span-ID: {:?}", user_id, resource_uri, context.get().0.clone());
        Err(ApiError("Generic failure".into()))
    }

    /// List user resources
    async fn get_user_resources(
        &self,
        user_id: String,
        resource_uri: Option<String>,
        collection_configuration: Option<String>,
        permissions: Option<String>,
        limit: Option<i32>,
        cursor: Option<String>,
        context: &C) -> Result<GetUserResourcesResponse, ApiError>
    {
        let context = context.clone();
        info!("get_user_resources({:?}, {:?}, {:?}, {:?}, {:?}, {:?}) - X-Span-ID: {:?}", user_id, resource_uri, collection_configuration, permissions, limit, cursor, context.get().0.clone());
        Err(ApiError("Generic failure".into()))
    }

    /// Get user roles for resource
    async fn get_user_roles_for_resource(
        &self,
        user_id: String,
        resource_uri: String,
        context: &C) -> Result<GetUserRolesForResourceResponse, ApiError>
    {
        let context = context.clone();
        info!("get_user_roles_for_resource({:?}, \"{}\") - X-Span-ID: {:?}", user_id, resource_uri, context.get().0.clone());
        Err(ApiError("Generic failure".into()))
    }

    /// Delete a user
    async fn delete_user(
        &self,
        user_id: String,
        context: &C) -> Result<DeleteUserResponse, ApiError>
    {
        let context = context.clone();
        info!("delete_user({:?}) - X-Span-ID: {:?}", user_id, context.get().0.clone());
        Err(ApiError("Generic failure".into()))
    }

    /// Retrieve a user
    async fn get_user(
        &self,
        user_id: String,
        context: &C) -> Result<GetUserResponse, ApiError>
    {
        let context = context.clone();
        info!("get_user({:?}) - X-Span-ID: {:?}", user_id, context.get().0.clone());
        Err(ApiError("Generic failure".into()))
    }

    /// List users
    async fn get_users(
        &self,
        limit: Option<i32>,
        cursor: Option<String>,
        filter: Option<String>,
        tenant_id: Option<String>,
        context: &C) -> Result<GetUsersResponse, ApiError>
    {
        let context = context.clone();
        info!("get_users({:?}, {:?}, {:?}, {:?}) - X-Span-ID: {:?}", limit, cursor, filter, tenant_id, context.get().0.clone());
        Err(ApiError("Generic failure".into()))
    }

}
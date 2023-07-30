//! Main library entry point for authress_local implementation.

// This is the implementation for the service

#![allow(unused_imports)]

use async_trait::async_trait;
use futures::{future, Stream, StreamExt, TryFutureExt, TryStreamExt};
use hyper::server::conn::Http;
use hyper::service::Service;
use log::*;
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

// use crate::models;
use authress::models::*;

use authress_local::*;
use authress_local::server::MakeService;
use std::error::Error;

use crate::databases::{Databases, self};

/// Builds an SSL implementation for Simple HTTPS from some hard-coded file names
pub async fn create(addr: &str, https: bool, databases: &'static Databases) {
    let addr = addr.parse().expect("Failed to parse bind address");

    let server = Server::new(&databases);

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
    databases: &'static Databases
}

impl<C> Server<C> {
    pub fn new(databases: &'static Databases) -> Self {
        Server {
            marker: PhantomData,
            databases: &databases
        }
    }
}

#[async_trait]
impl<C> Api<C> for Server<C> where C: Has<XSpanIdString> + Send + Sync
{
    /// Create resource Claim
    async fn create_claim(&self, claim_request: ClaimRequest, context: &C) -> Result<CreateClaimResponse,ApiError> {
        let context = context.clone();
        info!("create_claim({:?}) - X-Span-ID: {:?}", claim_request, context.get().0.clone());
        Err(ApiError::NotImplementedError("This endpoint is not yet implemented".into()))
    }

    /// Create user invite
    async fn create_invite(&self, invite: Invite, context: &C) -> Result<CreateInviteResponse,ApiError> {
        let context = context.clone();
        info!("create_invite({:?}) - X-Span-ID: {:?}", invite, context.get().0.clone());
        
        return Ok(CreateInviteResponse::Success("{}".to_string()));
    }

    /// Delete invite
    async fn delete_invite(&self, invite_id: String,context: &C) -> Result<DeleteInviteResponse, ApiError> {
        let context = context.clone();
        info!("delete_invite(\"{}\") - X-Span-ID: {:?}", invite_id, context.get().0.clone());
        Err(ApiError::NotImplementedError("This endpoint is not yet implemented".into()))
    }
    /// Accept invite
    async fn respond_to_invite(&self, invite_id: String,context: &C) -> Result<RespondToInviteResponse, ApiError> {
        let context = context.clone();
        info!("respond_to_invite(\"{}\") - X-Span-ID: {:?}", invite_id, context.get().0.clone());
        Err(ApiError::NotImplementedError("This endpoint is not yet implemented".into()))
    }

    /// Create access record
    async fn create_record(&self, access_record: AccessRecord, context: &C) -> Result<CreateRecordResponse,ApiError> {
        let context = context.clone();
        info!("create_record({:?}) - X-Span-ID: {:?}", access_record, context.get().0.clone());

        let record_id = access_record.record_id.unwrap_or(nanoid::nanoid!());
        let database_access_record = AccessRecord {
            record_id: Some(record_id.clone()),
            ..access_record
        };

        let mut database = self.databases.records_db.lock().unwrap();
        let result = database.get(&record_id);
        if let Some(_) = result {
            return Ok(CreateRecordResponse::AccessRecordAlreadyExists);
        }
        
        database.insert(record_id.to_string(), database_access_record);

        let result = database.get(&record_id);
        return Ok(CreateRecordResponse::Success {
            body: serde_json::to_string(&*result.unwrap()).unwrap(),
            last_modified: Some(chrono::offset::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
        });
    }

    /// Retrieve access record
    async fn get_record(&self, record_id: String,context: &C) -> Result<GetRecordResponse, ApiError> {
        let context = context.clone();
        info!("get_record(\"{}\") - X-Span-ID: {:?}", record_id, context.get().0.clone());
        
        let database = self.databases.records_db.lock().unwrap();
        let result = database.get(&record_id);
        if let Some(existing_access_record) = result {
            return Ok(GetRecordResponse::Success {
                body: serde_json::to_string(&*existing_access_record).unwrap(),
                last_modified: Some(chrono::offset::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
            });
        }

        return Ok(GetRecordResponse::NotFound);
    }

    /// List access records
    async fn get_records(&self, limit: Option<i32>, cursor: Option<String>, filter: Option<String>, status: Option<String>, context: &C) -> Result<GetRecordsResponse, ApiError> {
        let context = context.clone();
        info!("get_records({:?}, {:?}, {:?}, {:?}) - X-Span-ID: {:?}", limit, cursor, filter, status, context.get().0.clone());
        
        let database = self.databases.records_db.lock().unwrap();
        let records = database.values().cloned().collect::<Vec<AccessRecord>>();
        return Ok(GetRecordsResponse::Success(serde_json::to_string(&*records).unwrap()));
    }

    /// Update access record
    async fn update_record(&self, record_id: String, access_record: AccessRecord, if_unmodified_since: Option<String>, context: &C) -> Result<UpdateRecordResponse, ApiError> {
        let context = context.clone();
        info!("update_record(\"{}\", {:?}, {:?}) - X-Span-ID: {:?}", record_id, access_record, if_unmodified_since, context.get().0.clone());
        
        let mut database = self.databases.records_db.lock().unwrap();
        let result = database.get(&record_id);
        if let None = result {
            return Ok(UpdateRecordResponse::NotFound);
        }

        database.insert(record_id.to_string(), access_record);
        return Ok(UpdateRecordResponse::Success);
    }

    /// Deletes access record
    async fn delete_record(&self, record_id: String,context: &C) -> Result<DeleteRecordResponse, ApiError> {
        let context = context.clone();
        info!("delete_record(\"{}\") - X-Span-ID: {:?}", record_id, context.get().0.clone());
        
        let mut database = self.databases.records_db.lock().unwrap();
        database.remove(&record_id);
        return Ok(DeleteRecordResponse::Success);
    }

    /* ********************************* */

    /* ACCESS REQUESTS MANAGEMENT */

    /// Create access request
    async fn create_request(&self, access_request: AccessRequest,context: &C) -> Result<CreateRequestResponse, ApiError> {
        let context = context.clone();
        info!("create_request({:?}) - X-Span-ID: {:?}", access_request, context.get().0.clone());
        Err(ApiError::NotImplementedError("This endpoint is not yet implemented".into()))
    }

    /// Deletes access request
    async fn delete_request(&self, request_id: String,context: &C) -> Result<DeleteRequestResponse, ApiError> {
        let context = context.clone();
        info!("delete_request(\"{}\") - X-Span-ID: {:?}", request_id, context.get().0.clone());
        Err(ApiError::NotImplementedError("This endpoint is not yet implemented".into()))
    }

    /// Retrieve access request
    async fn get_request(&self, request_id: String,context: &C) -> Result<GetRequestResponse, ApiError> {
        let context = context.clone();
        info!("get_request(\"{}\") - X-Span-ID: {:?}", request_id, context.get().0.clone());
        Err(ApiError::NotImplementedError("This endpoint is not yet implemented".into()))
    }

    /// List access requests
    async fn get_requests(&self, limit: Option<i32>,cursor: Option<String>, status: Option<String>, context: &C) -> Result<GetRequestsResponse, ApiError> {
        let context = context.clone();
        info!("get_requests({:?}, {:?}, {:?}) - X-Span-ID: {:?}", limit, cursor, status, context.get().0.clone());
        Err(ApiError::NotImplementedError("This endpoint is not yet implemented".into()))
    }

    /// Approve or deny access request
    async fn respond_to_access_request(&self, request_id: String,access_request_response: AccessRequestResponse, context: &C) -> Result<RespondToAccessRequestResponse, ApiError> {
        let context = context.clone();
        info!("respond_to_access_request(\"{}\", {:?}) - X-Span-ID: {:?}", request_id, access_request_response, context.get().0.clone());
        Err(ApiError::NotImplementedError("This endpoint is not yet implemented".into()))
    }

    /* ACCOUNT MANAGER */
    /// Retrieve account information
    async fn get_account(&self, account_id: String,context: &C) -> Result<GetAccountResponse, ApiError> {
        let context = context.clone();
        info!("get_account(\"{}\") - X-Span-ID: {:?}", account_id, context.get().0.clone());
        Err(ApiError::NotImplementedError("This endpoint is not yet implemented".into()))
    }

    /// List user Authress accounts
    async fn get_accounts(&self, earliest_cache_time: Option<chrono::DateTime::<chrono::Utc>>,context: &C) -> Result<GetAccountsResponse, ApiError> {
        let context = context.clone();
        info!("get_accounts({:?}) - X-Span-ID: {:?}", earliest_cache_time, context.get().0.clone());
        Err(ApiError::NotImplementedError("This endpoint is not yet implemented".into()))
    }

    /// Link external provider
    async fn delegate_authentication(&self, identity_request: IdentityRequest,context: &C) -> Result<DelegateAuthenticationResponse, ApiError> {
        let context = context.clone();
        info!("delegate_authentication({:?}) - X-Span-ID: {:?}", identity_request, context.get().0.clone());
        Err(ApiError::NotImplementedError("This endpoint is not yet implemented".into()))
    }

    /// List linked external providers
    async fn get_account_identities(&self, context: &C) -> Result<GetAccountIdentitiesResponse,ApiError> {
        let context = context.clone();
        info!("get_account_identities() - X-Span-ID: {:?}", context.get().0.clone());
        Err(ApiError::NotImplementedError("This endpoint is not yet implemented".into()))
    }

    /* *************** */

    /* LOGIN MANAGEMENT */

    /// Create tenant
    async fn create_tenant(&self, tenant: Tenant,context: &C) -> Result<CreateTenantResponse, ApiError> {
        let context = context.clone();
        info!("create_tenant({:?}) - X-Span-ID: {:?}", tenant, context.get().0.clone());
        Err(ApiError::NotImplementedError("This endpoint is not yet implemented".into()))
    }

    /// Delete tenant
    async fn delete_tenant(&self, tenant_id: String,context: &C) -> Result<DeleteTenantResponse, ApiError> {
        let context = context.clone();
        info!("delete_tenant(\"{}\") - X-Span-ID: {:?}", tenant_id, context.get().0.clone());
        Err(ApiError::NotImplementedError("This endpoint is not yet implemented".into()))
    }

    /// Retrieve tenant
    async fn get_tenant(&self, tenant_id: String,context: &C) -> Result<GetTenantResponse, ApiError> {
        let context = context.clone();
        info!("get_tenant(\"{}\") - X-Span-ID: {:?}", tenant_id, context.get().0.clone());
        Err(ApiError::NotImplementedError("This endpoint is not yet implemented".into()))
    }

    /// List tenants
    async fn get_tenants(&self, context: &C) -> Result<GetTenantsResponse,ApiError> {
        let context = context.clone();
        info!("get_tenants() - X-Span-ID: {:?}", context.get().0.clone());
        Err(ApiError::NotImplementedError("This endpoint is not yet implemented".into()))
    }

    /// Update tenant
    async fn update_tenant(&self, tenant_id: String,tenant: Tenant, context: &C) -> Result<UpdateTenantResponse, ApiError> {
        let context = context.clone();
        info!("update_tenant(\"{}\", {:?}) - X-Span-ID: {:?}", tenant_id, tenant, context.get().0.clone());
        Err(ApiError::NotImplementedError("This endpoint is not yet implemented".into()))
    }

    /// Create SSO connection
    async fn create_connection(&self, connection: Connection,context: &C) -> Result<CreateConnectionResponse, ApiError> {
        let context = context.clone();
        info!("create_connection({:?}) - X-Span-ID: {:?}", connection, context.get().0.clone());
        Err(ApiError::NotImplementedError("This endpoint is not yet implemented".into()))
    }

    /// Delete SSO connection
    async fn delete_connection(&self, connection_id: String,context: &C) -> Result<DeleteConnectionResponse, ApiError> {
        let context = context.clone();
        info!("delete_connection(\"{}\") - X-Span-ID: {:?}", connection_id, context.get().0.clone());
        Err(ApiError::NotImplementedError("This endpoint is not yet implemented".into()))
    }

    /// Retrieve SSO connection
    async fn get_connection(&self, connection_id: String,context: &C) -> Result<GetConnectionResponse, ApiError> {
        let context = context.clone();
        info!("get_connection(\"{}\") - X-Span-ID: {:?}", connection_id, context.get().0.clone());
        Err(ApiError::NotImplementedError("This endpoint is not yet implemented".into()))
    }

    /// Retrieve user connection credentials
    async fn get_connection_credentials(&self, connection_id: String,user_id: String, context: &C) -> Result<GetConnectionCredentialsResponse, ApiError> {
        let context = context.clone();
        info!("get_connection_credentials(\"{}\", {:?}) - X-Span-ID: {:?}", connection_id, user_id, context.get().0.clone());
        Err(ApiError::NotImplementedError("This endpoint is not yet implemented".into()))
    }

    /// List SSO connections
    async fn get_connections(&self, context: &C) -> Result<GetConnectionsResponse,ApiError> {
        let context = context.clone();
        info!("get_connections() - X-Span-ID: {:?}", context.get().0.clone());
        Err(ApiError::NotImplementedError("This endpoint is not yet implemented".into()))
    }

    /// Update SSO connection
    async fn update_connection(&self, connection_id: String,connection: Connection, context: &C) -> Result<UpdateConnectionResponse, ApiError> {
        let context = context.clone();
        info!("update_connection(\"{}\", {:?}) - X-Span-ID: {:?}", connection_id, connection, context.get().0.clone());
        Err(ApiError::NotImplementedError("This endpoint is not yet implemented".into()))
    }

    /// Create extension
    async fn create_extension(&self, extension: Extension,context: &C) -> Result<CreateExtensionResponse, ApiError> {
        let context = context.clone();
        info!("create_extension({:?}) - X-Span-ID: {:?}", extension, context.get().0.clone());
        Err(ApiError::NotImplementedError("This endpoint is not yet implemented".into()))
    }

    /// Delete extension
    async fn delete_extension(&self, extension_id: String,context: &C) -> Result<DeleteExtensionResponse, ApiError> {
        let context = context.clone();
        info!("delete_extension(\"{}\") - X-Span-ID: {:?}", extension_id, context.get().0.clone());
        Err(ApiError::NotImplementedError("This endpoint is not yet implemented".into()))
    }

    /// Retrieve extension
    async fn get_extension(&self, extension_id: String,context: &C) -> Result<GetExtensionResponse, ApiError> {
        let context = context.clone();
        info!("get_extension(\"{}\") - X-Span-ID: {:?}", extension_id, context.get().0.clone());
        Err(ApiError::NotImplementedError("This endpoint is not yet implemented".into()))
    }

    /// List extensions
    async fn get_extensions(&self, context: &C) -> Result<GetExtensionsResponse,ApiError> {
        let context = context.clone();
        info!("get_extensions() - X-Span-ID: {:?}", context.get().0.clone());
        Err(ApiError::NotImplementedError("This endpoint is not yet implemented".into()))
    }

    /// Update extension
    async fn update_extension(&self, extension_id: String,extension: Extension, context: &C) -> Result<UpdateExtensionResponse, ApiError> {
        let context = context.clone();
        info!("update_extension(\"{}\", {:?}) - X-Span-ID: {:?}", extension_id, extension, context.get().0.clone());
        Err(ApiError::NotImplementedError("This endpoint is not yet implemented".into()))
    }

    /// Log user into third-party application
    async fn delegate_user_login(&self, application_id: String,user_id: String, context: &C) -> Result<DelegateUserLoginResponse, ApiError> {
        let context = context.clone();
        info!("delegate_user_login(\"{}\", {:?}) - X-Span-ID: {:?}", application_id, user_id, context.get().0.clone());
        Err(ApiError::NotImplementedError("This endpoint is not yet implemented".into()))
    }

    /// OAuth Authorize
    async fn login(&self, client_id: String,code_challenge: String, redirect_uri: String, code_challenge_method: Option<String>, context: &C) -> Result<LoginResponse, ApiError> {
        let context = context.clone();
        info!("login(\"{}\", \"{}\", \"{}\", {:?}) - X-Span-ID: {:?}", client_id, code_challenge, redirect_uri, code_challenge_method, context.get().0.clone());
        Err(ApiError::NotImplementedError("This endpoint is not yet implemented".into()))
    }

    /// OAuth Token
    async fn request_token(&self, o_auth_token_request: OAuthTokenRequest,context: &C) -> Result<RequestTokenResponse, ApiError> {
        let context = context.clone();
        info!("request_token({:?}) - X-Span-ID: {:?}", o_auth_token_request, context.get().0.clone());
        Err(ApiError::NotImplementedError("This endpoint is not yet implemented".into()))
    }

    /* ********************************* */

    /* GROUP MANAGEMENT */

    async fn create_group(&self, group: Group, context: &C) -> Result<CreateGroupResponse,ApiError> {
        let context = context.clone();
        info!("create_group({:?}) - X-Span-ID: {:?}", group, context.get().0.clone());
    
        let group_id_option = group.group_id.clone();
        if let Some(group_id) = group_id_option {
            if !group_id.starts_with("grp_") {
                return Err(ApiError::UnknownApiError("Group IDs must start with the prefix grp_".to_string()));
            }
        }

        let group_id = group.group_id.unwrap_or(nanoid::nanoid!());
        let database_group = Group {
            group_id: Some(group_id.clone()),
            ..group
        };
    
        let mut database = self.databases.groups_db.lock().unwrap();
        let result = database.get(&group_id);
        if let Some(_) = result {
            return Ok(CreateGroupResponse::GroupAlreadyExists);
        }
        
        database.insert(group_id.to_string(), database_group);
    
        let result = database.get(&group_id);
        return Ok(CreateGroupResponse::Success(serde_json::to_string(&*result.unwrap()).unwrap()));
    }
    
    /// Retrieve group
    async fn get_group(&self, group_id: String,context: &C) -> Result<GetGroupResponse, ApiError> {
        let context = context.clone();
        info!("get_group(\"{}\") - X-Span-ID: {:?}", group_id, context.get().0.clone());
        
        let database = self.databases.groups_db.lock().unwrap();
        let result = database.get(&group_id);
        if let Some(existing_group) = result {
            return Ok(GetGroupResponse::Success(serde_json::to_string(&*existing_group).unwrap()));
        }
    
        return Ok(GetGroupResponse::NotFound);
    }
    
    /// List groups
    async fn get_groups(&self, limit: Option<i32>, cursor: Option<String>, filter: Option<String>, context: &C) -> Result<GetGroupsResponse, ApiError> {
        let context = context.clone();
        info!("get_groups({:?}, {:?}, {:?}) - X-Span-ID: {:?}", limit, cursor, filter, context.get().0.clone());
        
        let database = self.databases.groups_db.lock().unwrap();
        let groups = database.values().cloned().collect::<Vec<Group>>();
        return Ok(GetGroupsResponse::Success(serde_json::to_string(&*groups).unwrap()));
    }
    
    /// Update group
    async fn update_group(&self, group_id: String, group: Group, context: &C) -> Result<UpdateGroupResponse, ApiError> {
        let context = context.clone();
        info!("update_group(\"{}\", {:?}) - X-Span-ID: {:?}", group_id, group, context.get().0.clone());
        
        let mut database = self.databases.groups_db.lock().unwrap();
        let result = database.get(&group_id);
        if let None = result {
            return Ok(UpdateGroupResponse::NotFound);
        }
    
        database.insert(group_id.to_string(), group.clone());
        return Ok(UpdateGroupResponse::Success(serde_json::to_string(&group).unwrap()));
    }
    
    /// Deletes group
    async fn delete_group(&self, group_id: String,context: &C) -> Result<DeleteGroupResponse, ApiError> {
        let context = context.clone();
        info!("delete_record(\"{}\") - X-Span-ID: {:?}", group_id, context.get().0.clone());
        
        let mut database = self.databases.groups_db.lock().unwrap();
        database.remove(&group_id);
        return Ok(DeleteGroupResponse::Success);
    }

    /* ********************************* */

    /* RESOURCE MANAGEMENT */

    /// Retrieve resource configuration
    async fn get_permissioned_resource(&self, resource_uri: String,context: &C) -> Result<GetPermissionedResourceResponse, ApiError> {
        let context = context.clone();
        info!("get_permissioned_resource(\"{}\") - X-Span-ID: {:?}", resource_uri, context.get().0.clone());
        Err(ApiError::NotImplementedError("This endpoint is not yet implemented".into()))
    }

    /// List all resource configurations
    async fn get_permissioned_resources(&self, context: &C) -> Result<GetPermissionedResourcesResponse,ApiError> {
        let context = context.clone();
        info!("get_permissioned_resources() - X-Span-ID: {:?}", context.get().0.clone());
        Err(ApiError::NotImplementedError("This endpoint is not yet implemented".into()))
    }

    /// List users with resource access
    async fn get_resource_users(&self, resource_uri: String,limit: Option<i32>, cursor: Option<String>, context: &C) -> Result<GetResourceUsersResponse, ApiError> {
        let context = context.clone();
        info!("get_resource_users(\"{}\", {:?}, {:?}) - X-Span-ID: {:?}", resource_uri, limit, cursor, context.get().0.clone());
        Err(ApiError::NotImplementedError("This endpoint is not yet implemented".into()))
    }

    /// Update resource configuration
    async fn update_permissioned_resource(&self, resource_uri: String,permissioned_resource: PermissionedResource, context: &C) -> Result<UpdatePermissionedResourceResponse, ApiError> {
        let context = context.clone();
        info!("update_permissioned_resource(\"{}\", {:?}) - X-Span-ID: {:?}", resource_uri, permissioned_resource, context.get().0.clone());
        Err(ApiError::NotImplementedError("This endpoint is not yet implemented".into()))
    }

    /* ********************************* */

    /* ROLE MANAGEMENT */

    
    // Create role
    async fn create_role(&self, role: Role, context: &C) -> Result<CreateRoleResponse,ApiError> {
        let context = context.clone();
        info!("create_role({:?}) - X-Span-ID: {:?}", role, context.get().0.clone());
    
        if !role.role_id.starts_with("ro_") {
            return Err(ApiError::UnknownApiError("Role IDs must start with the prefix ro_".to_string()));
        }

        let role_id = role.role_id.clone();
        let mut database = self.databases.roles_db.lock().unwrap();
        let result = database.get(&role_id);
        if let Some(_) = result {
            return Ok(CreateRoleResponse::RoleAlreadyExists);
        }
        
        database.insert(role_id.to_string(), role.clone());
    
        let result = database.get(&role_id);
        return Ok(CreateRoleResponse::Success(serde_json::to_string(&*result.unwrap()).unwrap()));
    }
    
    /// Retrieve role
    async fn get_role(&self, role_id: String,context: &C) -> Result<GetRoleResponse, ApiError> {
        let context = context.clone();
        info!("get_role(\"{}\") - X-Span-ID: {:?}", role_id, context.get().0.clone());
        
        let database = self.databases.roles_db.lock().unwrap();
        let result = database.get(&role_id);
        if let Some(existing_role) = result {
            return Ok(GetRoleResponse::Success(serde_json::to_string(&*existing_role).unwrap()));
        }
    
        return Ok(GetRoleResponse::NotFound);
    }
    
    /// List roles
    async fn get_roles(&self, context: &C) -> Result<GetRolesResponse, ApiError> {
        let context = context.clone();
        info!("get_roles() - X-Span-ID: {:?}", context.get().0.clone());
        
        let database = self.databases.roles_db.lock().unwrap();
        let roles = database.values().cloned().collect::<Vec<Role>>();
        return Ok(GetRolesResponse::Success(serde_json::to_string(&*roles).unwrap()));
    }
    
    /// Update role
    async fn update_role(&self, role_id: String, role: Role, context: &C) -> Result<UpdateRoleResponse, ApiError> {
        let context = context.clone();
        info!("update_role(\"{}\", {:?}) - X-Span-ID: {:?}", role_id, role, context.get().0.clone());
        
        let mut database = self.databases.roles_db.lock().unwrap();
        let result = database.get(&role_id);
        if let None = result {
            return Ok(UpdateRoleResponse::NotFound);
        }
    
        database.insert(role_id.to_string(), role.clone());
        return Ok(UpdateRoleResponse::Success(serde_json::to_string(&role).unwrap()));
    }
    
    /// Deletes role
    async fn delete_role(&self, role_id: String,context: &C) -> Result<DeleteRoleResponse, ApiError> {
        let context = context.clone();
        info!("delete_record(\"{}\") - X-Span-ID: {:?}", role_id, context.get().0.clone());
        
        let mut database = self.databases.roles_db.lock().unwrap();
        database.remove(&role_id);
        return Ok(DeleteRoleResponse::Success);
    }

    /* ********************************* */

    /* SERVICE CLIENTS */

    /// Create service client
    async fn create_client(&self, client: Client,context: &C) -> Result<CreateClientResponse, ApiError> {
        let context = context.clone();
        info!("create_client({:?}) - X-Span-ID: {:?}", client, context.get().0.clone());
        Err(ApiError::NotImplementedError("This endpoint is not yet implemented".into()))
    }

    /// Delete service client access key
    async fn delete_access_key(&self, client_id: String,key_id: String, context: &C) -> Result<DeleteAccessKeyResponse, ApiError> {
        let context = context.clone();
        info!("delete_access_key(\"{}\", \"{}\") - X-Span-ID: {:?}", client_id, key_id, context.get().0.clone());
        Err(ApiError::NotImplementedError("This endpoint is not yet implemented".into()))
    }

    /// Delete service client
    async fn delete_client(&self, client_id: String,context: &C) -> Result<DeleteClientResponse, ApiError> {
        let context = context.clone();
        info!("delete_client(\"{}\") - X-Span-ID: {:?}", client_id, context.get().0.clone());
        Err(ApiError::NotImplementedError("This endpoint is not yet implemented".into()))
    }

    /// Retrieve service client
    async fn get_client(&self, client_id: String,context: &C) -> Result<GetClientResponse, ApiError> {
        let context = context.clone();
        info!("get_client(\"{}\") - X-Span-ID: {:?}", client_id, context.get().0.clone());
        Err(ApiError::NotImplementedError("This endpoint is not yet implemented".into()))
    }

    /// List service clients
    async fn get_clients(&self, limit: Option<i32>,cursor: Option<String>, context: &C) -> Result<GetClientsResponse, ApiError> {
        let context = context.clone();
        info!("get_clients({:?}, {:?}) - X-Span-ID: {:?}", limit, cursor, context.get().0.clone());
        Err(ApiError::NotImplementedError("This endpoint is not yet implemented".into()))
    }

    /// Generate service client access key
    async fn request_access_key(&self, client_id: String,context: &C) -> Result<RequestAccessKeyResponse, ApiError> {
        let context = context.clone();
        info!("request_access_key(\"{}\") - X-Span-ID: {:?}", client_id, context.get().0.clone());
        Err(ApiError::NotImplementedError("This endpoint is not yet implemented".into()))
    }

    /// Update service client
    async fn update_client(&self, client_id: String,client: Client, context: &C) -> Result<UpdateClientResponse, ApiError> {
        let context = context.clone();
        info!("update_client(\"{}\", {:?}) - X-Span-ID: {:?}", client_id, client, context.get().0.clone());
        Err(ApiError::NotImplementedError("This endpoint is not yet implemented".into()))
    }

    /* ********************************* */

    /* USER PERMISSIONS */

    /// Verify user authorization
    async fn authorize_user(&self, user_id: String,resource_uri: String, permission: String, context: &C) -> Result<AuthorizeUserResponse, ApiError> {
        let context = context.clone();
        info!("authorize_user({:?}, \"{}\", {:?}) - X-Span-ID: {:?}", user_id, resource_uri, permission, context.get().0.clone());
        
        return Ok(AuthorizeUserResponse::Success);
    }

    /// Get user permissions for resource
    async fn get_user_permissions_for_resource(&self, user_id: String, resource_uri: String, context: &C) -> Result<GetUserPermissionsForResourceResponse, ApiError> {
        let context = context.clone();
        info!("get_user_permissions_for_resource({:?}, \"{}\") - X-Span-ID: {:?}", user_id, resource_uri, context.get().0.clone());
        
        let permission_collection = PermissionCollection {
            permissions: vec![PermissionObject { action: "*".to_string(), allow: true, grant: true, delegate: true, ..Default::default() } ],
            ..Default::default()
        };
        return Ok(GetUserPermissionsForResourceResponse::Success(serde_json::to_string(&permission_collection).unwrap()));
    }

    /// List user resources
    async fn get_user_resources(&self, user_id: String, resource_uri: Option<String>, collection_configuration: Option<String>, permissions: Option<String>, limit: Option<i32>, cursor: Option<String>,
        context: &C) -> Result<GetUserResourcesResponse, ApiError> {

        let context = context.clone();
        info!("get_user_resources({:?}, {:?}, {:?}, {:?}, {:?}, {:?}) - X-Span-ID: {:?}", user_id, resource_uri, collection_configuration, permissions, limit, cursor, context.get().0.clone());
        
        let database = self.databases.records_db.lock().unwrap();
        let records = database.values().cloned().collect::<Vec<AccessRecord>>();

        let user_resources_collection = UserResourcesCollection {
            user_id,
            resources: Some(records
                .into_iter().map(|record| record.statements
                    .into_iter().map(|statement| statement.resources
                        .into_iter().map(|resource| resource.resource_uri)
                        .collect::<Vec<String>>()
                    ).collect::<Vec<Vec<String>>>()
                ).collect::<Vec<Vec<Vec<String>>>>().into_iter().flatten().flatten().map(|resource_uri| Resource { resource_uri: resource_uri }).collect()),
            ..Default::default()
        };

        return Ok(GetUserResourcesResponse::Success(serde_json::to_string(&user_resources_collection).unwrap()));
    }

    /// Get user roles for resource
    async fn get_user_roles_for_resource(&self, user_id: String,resource_uri: String, context: &C) -> Result<GetUserRolesForResourceResponse, ApiError> {
        let context = context.clone();
        info!("get_user_roles_for_resource({:?}, \"{}\") - X-Span-ID: {:?}", user_id, resource_uri, context.get().0.clone());
        
        let database = self.databases.roles_db.lock().unwrap();
        let roles = database.values().cloned().collect::<Vec<Role>>();
        
        let role_collection = UserRoleCollection {
            roles: roles.into_iter().map(|role| UserRole { role_id: role.role_id, ..Default::default() }).collect::<Vec<UserRole>>(),
            ..Default::default()
        };
        return Ok(GetUserRolesForResourceResponse::Success(serde_json::to_string(&role_collection).unwrap()));
    }

    /* ********************************* */

    /* USER MANAGEMENT */

    /// Delete a user
    async fn delete_user(&self, user_id: String,context: &C) -> Result<DeleteUserResponse, ApiError> {
        let context = context.clone();
        info!("delete_user({:?}) - X-Span-ID: {:?}", user_id, context.get().0.clone());
        Err(ApiError::NotImplementedError("This endpoint is not yet implemented".into()))
    }

    /// Retrieve a user
    async fn get_user(&self, user_id: String,context: &C) -> Result<GetUserResponse, ApiError> {
        let context = context.clone();
        info!("get_user({:?}) - X-Span-ID: {:?}", user_id, context.get().0.clone());
        Err(ApiError::NotImplementedError("This endpoint is not yet implemented".into()))
    }

    /// List users
    async fn get_users(&self, limit: Option<i32>,cursor: Option<String>, filter: Option<String>, tenant_id: Option<String>, context: &C) -> Result<GetUsersResponse, ApiError> {
        let context = context.clone();
        info!("get_users({:?}, {:?}, {:?}, {:?}) - X-Span-ID: {:?}", limit, cursor, filter, tenant_id, context.get().0.clone());
        Err(ApiError::NotImplementedError("This endpoint is not yet implemented".into()))
    }

}

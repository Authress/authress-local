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

type ServiceError = Box<dyn Error + Send + Sync + 'static>;

pub struct UnknownApiError(pub String);
pub struct NotImplementedError(pub String);

pub enum ApiError {
    NotImplementedError(String),
    UnknownApiError(String)
    
}

pub const BASE_PATH: &str = "";
pub const API_VERSION: &str = "v1";

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum CreateClaimResponse {
    /// Success. Resource claimed.
    Success
    (String)
    ,
    /// Unauthorized. The request JWT found in the Authorization header is no longer valid.
    Unauthorized
    ,
    /// Forbidden. The user doesn't have permission to the resource collection to claim a sub-resource.
    Forbidden
    ,
    /// AlreadyClaimed. The resource has already been claimed by another user or another user already has access to this resource. So admin access will not be given. The reason for this is to prevent preemptive stealing of admin access to these records.
    AlreadyClaimed
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum CreateInviteResponse {
    /// Success. Invite created
    Success
    (String)
    ,
    /// Unauthorized. The request JWT found in the Authorization header is no longer valid.
    Unauthorized
    ,
    /// Forbidden. The user doesn't have the permissions to create an invite. They may have specified too many permissions in the invite.
    Forbidden
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum CreateRecordResponse {
    /// Success. Access record created
    Success
    {
        body: String,
        last_modified: Option<String>
    },
    /// Unauthorized. The request JWT found in the Authorization header is no longer valid.
    Unauthorized,
    /// Forbidden. The user doesn't have permission to create records.
    Forbidden,
    /// The size of the record is larger than allowed. Recommended action is to create another record and retry the updates.
    TheSizeOfTheRecordIsLargerThanAllowed,
    /// AccessRecordAlreadyExists. There already exists an access record with this recordId.
    AccessRecordAlreadyExists
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum CreateRequestResponse {
    /// Success. Access request created
    Success
    (String)
    ,
    /// Unauthorized. The request JWT found in the Authorization header is no longer valid.
    Unauthorized
    ,
    /// Forbidden. The user doesn't have permission to create access requests.
    Forbidden
    ,
    /// Unprocessable Entity. Some of the data in the request is invalid.
    UnprocessableEntity
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum DeleteInviteResponse {
    /// Success. Invite deleted.
    Success
    ,
    /// Unauthorized. The request JWT found in the Authorization header is no longer valid.
    Unauthorized
    ,
    /// Forbidden. The user doesn't have permission to delete the invite.
    Forbidden
    ,
    /// Not found. The user doesn't have any permissions to the invite.
    NotFound
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum DeleteRecordResponse {
    /// Success. The access record has been deleted
    Success
    ,
    /// Unauthorized. The request JWT found in the Authorization header is no longer valid.
    Unauthorized
    ,
    /// Forbidden. The user doesn't have permission to delete the access record.
    Forbidden
    ,
    /// Not found. The user doesn't have any permissions to the resource or the access record no longer exists.
    NotFound
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum DeleteRequestResponse {
    /// Success. The access request has been deleted
    Success
    ,
    /// Unauthorized. The request JWT found in the Authorization header is no longer valid.
    Unauthorized
    ,
    /// Forbidden. The user doesn't have permission to delete the access request.
    Forbidden
    ,
    /// Not found. The user doesn't have any permissions to the access request or it no longer exists.
    NotFound
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum GetRecordResponse {
    /// Success.
    Success
    {
        body: String,
        last_modified:
        Option<
        String
        >
    }
    ,
    /// Unauthorized. The request JWT found in the Authorization header is no longer valid.
    Unauthorized
    ,
    /// Forbidden. The user doesn't have permission to the access record, but they have other permissions to the same account.
    Forbidden
    ,
    /// Not found. The user doesn't have any permissions to the access record or this access record does not exist.
    NotFound
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum GetRecordsResponse {
    /// Success.
    Success
    (String)
    ,
    /// Unauthorized. The request JWT found in the Authorization header is no longer valid.
    Unauthorized
    ,
    /// Forbidden. The user doesn't have permission to fetch account records, but has other account permissions.
    Forbidden
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum GetRequestResponse {
    /// Success.
    Success
    (String)
    ,
    /// Unauthorized. The request JWT found in the Authorization header is no longer valid.
    Unauthorized
    ,
    /// Forbidden. The user doesn't have permission to the access request, but they have other permissions to the same account.
    Forbidden
    ,
    /// Not found. The user doesn't have any permissions to the access request or this access request does not exist.
    NotFound
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum GetRequestsResponse {
    /// Success.
    Success
    (String)
    ,
    /// Unauthorized. The request JWT found in the Authorization header is no longer valid.
    Unauthorized
    ,
    /// Forbidden. The user doesn't have permission to fetch access requests, but has other account permissions.
    Forbidden
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum RespondToAccessRequestResponse {
    /// Success. Access record updated.
    Success
    (String)
    ,
    /// Unauthorized. The request JWT found in the Authorization header is no longer valid.
    Unauthorized
    ,
    /// Forbidden. The user doesn't have permission to update the access request.
    Forbidden
    ,
    /// Not found. The user doesn't have any permissions to the access request.
    NotFound
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum RespondToInviteResponse {
    /// Success. Invite accepted.
    Success
    (String)
    ,
    /// Unauthorized. The request JWT found in the Authorization header is no longer valid.
    Unauthorized
    ,
    /// Forbidden. The user doesn't have permission to update the access record.
    Forbidden
    ,
    /// Not found. The user doesn't have any permissions to the access record.
    NotFound
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum UpdateRecordResponse {
    /// Success. Access record update request was accepted.
    Success
    ,
    /// Unauthorized. The request JWT found in the Authorization header is no longer valid.
    Unauthorized
    ,
    /// Forbidden. The user doesn't have permission to update the access record.
    Forbidden
    ,
    /// Not found. The user doesn't have any permissions to the access record.
    NotFound
    ,
    /// Precondition failed. Usually the result of a concurrent update to the access record. Get the latest version and retry again.
    PreconditionFailed
    {
        last_modified:
        Option<
        String
        >
    }
    ,
    /// The size of the record is larger than allowed. Recommended action is to create another record and retry the updates.
    TheSizeOfTheRecordIsLargerThanAllowed
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum DelegateAuthenticationResponse {
    /// Success. New identity linked.
    Success
    ,
    /// Unauthorized. The request JWT found in the Authorization header is no longer valid.
    Unauthorized
    ,
    /// Forbidden. The user doesn't have permission to update identities for the account.
    Forbidden
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum GetAccountResponse {
    /// Success. The account
    Success
    (String)
    ,
    /// Unauthorized. The request JWT found in the Authorization header is no longer valid.
    Unauthorized
    ,
    /// Not found. The user doesn't have any permissions to this account or it does not exist.
    NotFound
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum GetAccountIdentitiesResponse {
    /// Success.
    Success
    (String)
    ,
    /// Unauthorized. The request JWT found in the Authorization header is no longer valid.
    Unauthorized
    ,
    /// Not found. The user doesn't have permission to list identities for this account.
    NotFound
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum GetAccountsResponse {
    /// Success.
    Success
    (String)
    ,
    /// Unauthorized. The request JWT found in the Authorization header is no longer valid.
    Unauthorized
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum DelegateUserLoginResponse {
    /// Success.
    Success
    (String)
    ,
    /// Unauthorized. The request JWT found in the Authorization header is no longer valid.
    Unauthorized
    ,
    /// Forbidden. The user doesn't have permission to log a user into this application.
    Forbidden
    ,
    /// Not found. The application or user does not exist.
    NotFound
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum CreateConnectionResponse {
    /// Success. Connection created
    Success
    (String)
    ,
    /// Unauthorized. The request JWT found in the Authorization header is no longer valid.
    Unauthorized
    ,
    /// Forbidden. The user doesn't have permission to create connection.
    Forbidden
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum DeleteConnectionResponse {
    /// Success. Connection deleted
    Success
    ,
    /// Unauthorized. The request JWT found in the Authorization header is no longer valid.
    Unauthorized
    ,
    /// Forbidden. The user doesn't have permission to delete connection.
    Forbidden
    ,
    /// Not found. The connection does not exist.
    NotFound
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum GetConnectionResponse {
    /// Success.
    Success
    (String)
    ,
    /// Unauthorized. The request JWT found in the Authorization header is no longer valid.
    Unauthorized
    ,
    /// Forbidden. The user doesn't have permission to get connection.
    Forbidden
    ,
    /// Not found. The connection does not exist.
    NotFound
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum GetConnectionCredentialsResponse {
    /// Success.
    Success
    (String)
    ,
    /// Unauthorized. The request JWT found in the Authorization header is no longer valid.
    Unauthorized
    ,
    /// Forbidden. The user doesn't have permission to get user connection credentials.
    Forbidden
    ,
    /// Not found. The connection or user does not exist.
    NotFound
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum GetConnectionsResponse {
    /// Success.
    Success
    (String)
    ,
    /// Unauthorized. The request JWT found in the Authorization header is no longer valid.
    Unauthorized
    ,
    /// Forbidden. The user doesn't have permission to fetch account connections, but has other account permissions.
    Forbidden
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum UpdateConnectionResponse {
    /// Success. Connection updated
    Success
    (String)
    ,
    /// Unauthorized. The request JWT found in the Authorization header is no longer valid.
    Unauthorized
    ,
    /// Forbidden. The user doesn't have permission to update connection.
    Forbidden
    ,
    /// Not found. The connection does not exist.
    NotFound
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum CreateExtensionResponse {
    /// Success. Extension created
    Success
    (String)
    ,
    /// Unauthorized. The request JWT found in the Authorization header is no longer valid.
    Unauthorized
    ,
    /// Forbidden. The user doesn't have permission to create extension.
    Forbidden
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum DeleteExtensionResponse {
    /// Success. Extension deleted. Completed disabling and deleting an extension is done asynchronously.
    Success
    ,
    /// Unauthorized. The request JWT found in the Authorization header is no longer valid.
    Unauthorized
    ,
    /// Forbidden. The user doesn't have permission to delete extension.
    Forbidden
    ,
    /// Not found. The extension does not exist.
    NotFound
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum GetExtensionResponse {
    /// Success.
    Success
    (String)
    ,
    /// Unauthorized. The request JWT found in the Authorization header is no longer valid.
    Unauthorized
    ,
    /// Forbidden. The user doesn't have permission to get extension.
    Forbidden
    ,
    /// Not found. The extension does not extension.
    NotFound
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum GetExtensionsResponse {
    /// Success.
    Success
    (String)
    ,
    /// Unauthorized. The request JWT found in the Authorization header is no longer valid.
    Unauthorized
    ,
    /// Forbidden. The user doesn't have permission to fetch account extensions, but has other account permissions.
    Forbidden
}

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
pub enum UpdateExtensionResponse {
    /// Success. The extension has been successfully updated
    Success
    (String)
    ,
    /// Unauthorized. The request JWT found in the Authorization header is no longer valid.
    Unauthorized
    ,
    /// Forbidden. The user doesn't have permission to update extension.
    Forbidden
    ,
    /// Not found. The extension does not exist.
    NotFound
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum CreateGroupResponse {
    /// Success. Group created
    Success
    (String)
    ,
    /// Unauthorized. The request JWT found in the Authorization header is no longer valid.
    Unauthorized
    ,
    /// Forbidden. The user doesn't have permission to create groups.
    Forbidden
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum DeleteGroupResponse {
    /// Success. The group has been deleted
    Success
    ,
    /// Unauthorized. The request JWT found in the Authorization header is no longer valid.
    Unauthorized
    ,
    /// Forbidden. The user doesn't have permission to delete the group.
    Forbidden
    ,
    /// Not found. The user doesn't have any permissions to the resource or the group no longer exists.
    NotFound
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum GetGroupResponse {
    /// Success.
    Success
    (String)
    ,
    /// Unauthorized. The request JWT found in the Authorization header is no longer valid.
    Unauthorized
    ,
    /// Forbidden. The user doesn't have permission to the group, but they have other permissions to the same account.
    Forbidden
    ,
    /// Not found. The user doesn't have any permissions to the group or this group does not exist.
    NotFound
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum GetGroupsResponse {
    /// Success.
    Success
    (String)
    ,
    /// Unauthorized. The request JWT found in the Authorization header is no longer valid.
    Unauthorized
    ,
    /// Forbidden. The user doesn't have permission to fetch groups, but has other account permissions
    Forbidden
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum UpdateGroupResponse {
    /// Success. Group updated.
    Success
    (String)
    ,
    /// Unauthorized. The request JWT found in the Authorization header is no longer valid.
    Unauthorized
    ,
    /// Forbidden. The user doesn't have permission to update the group.
    Forbidden
    ,
    /// Not found. The user doesn't have any permissions to the group.
    NotFound
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum GetPermissionedResourceResponse {
    /// Success.
    Success
    (String)
    ,
    /// Unauthorized. The request JWT found in the Authorization header is no longer valid.
    Unauthorized
    ,
    /// Not found. The user doesn't have permission to the resource.
    NotFound
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum GetPermissionedResourcesResponse {
    /// Success.
    Success
    (String)
    ,
    /// Unauthorized. The request JWT found in the Authorization header is no longer valid.
    Unauthorized
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum GetResourceUsersResponse {
    /// Success.
    Success
    (String)
    ,
    /// Unauthorized. The request JWT found in the Authorization header is no longer valid.
    Unauthorized
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum UpdatePermissionedResourceResponse {
    /// Success.
    Success
    ,
    /// Unauthorized. The request JWT found in the Authorization header is no longer valid.
    Unauthorized
    ,
    /// Forbidden. The user doesn't have permission to the resource, but they have other permissions to the same resource.
    Forbidden
    ,
    /// Not found. The user doesn't have permission to the resource.
    NotFound
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum CreateRoleResponse {
    /// Success. Role created.
    Success
    (String)
    ,
    /// Unauthorized. The request JWT found in the Authorization header is no longer valid.
    Unauthorized
    ,
    /// Forbidden. The user doesn't have permission to the role, but they have other permissions to the same account.
    Forbidden
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum DeleteRoleResponse {
    /// Success. The role has been deleted
    Success
    ,
    /// Unauthorized. The request JWT found in the Authorization header is no longer valid.
    Unauthorized
    ,
    /// Forbidden. The user doesn't have permission to delete the role.
    Forbidden
    ,
    /// Not found. The user doesn't have any permissions to the resource or the role no longer exists.
    NotFound
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum GetRoleResponse {
    /// Success.
    Success
    (String)
    ,
    /// Unauthorized. The request JWT found in the Authorization header is no longer valid.
    Unauthorized
    ,
    /// Forbidden. The user doesn't have permission to the role, but they have other permissions to the same account.
    Forbidden
    ,
    /// Not found. The user doesn't have any permissions to the role or this role does not exist.
    NotFound
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum GetRolesResponse {
    /// Success.
    Success
    (String)
    ,
    /// Unauthorized. The request JWT found in the Authorization header is no longer valid.
    Unauthorized
    ,
    /// Forbidden. The user doesn't have permission to account roles, but they have other permissions to the same account.
    Forbidden
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum UpdateRoleResponse {
    /// Success. Role updated.
    Success
    (String)
    ,
    /// Unauthorized. The request JWT found in the Authorization header is no longer valid.
    Unauthorized
    ,
    /// Forbidden. The user doesn't have permission to the role, but they have other permissions to the same account.
    Forbidden
    ,
    /// Not found. The user doesn't have any permissions to the role or this role does not exist.
    NotFound
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum CreateClientResponse {
    /// Success.
    Success
    (String)
    ,
    /// Unauthorized. The request JWT found in the Authorization header is no longer valid.
    Unauthorized
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum DeleteAccessKeyResponse {
    /// Success. The access key has been deleted.
    Success
    ,
    /// Unauthorized. The request JWT found in the Authorization header is no longer valid.
    Unauthorized
    ,
    /// Forbidden. The user doesn't have permission to delete access keys from a client.
    Forbidden
    ,
    /// Not found. The user doesn't have any permissions to the client or the client does not exist.
    NotFound
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum DeleteClientResponse {
    /// Success. The client was deleted.
    Success
    ,
    /// Unauthorized. The request JWT found in the Authorization header is no longer valid.
    Unauthorized
    ,
    /// Forbidden. The user doesn't have permission to delete the client.
    Forbidden
    ,
    /// Not found. The user doesn't have any permission to the client or the client does not exist
    NotFound
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum GetClientResponse {
    /// Success.
    Success
    (String)
    ,
    /// Unauthorized. The request JWT found in the Authorization header is no longer valid.
    Unauthorized
    ,
    /// Not found. The user doesn't have permissions to the client or the client does not exist.
    NotFound
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum GetClientsResponse {
    /// Success.
    Success
    (String)
    ,
    /// Unauthorized. The request JWT found in the Authorization header is no longer valid.
    Unauthorized
    ,
    /// Forbidden. The user doesn't have permission to the resource, but they have other permissions to the same resource.
    Forbidden
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum RequestAccessKeyResponse {
    /// Success
    Success
    (String)
    ,
    /// Unauthorized. The request JWT found in the Authorization header is no longer valid.
    Unauthorized
    ,
    /// Forbidden. The user doesn't have permission to create access keys for the client.
    Forbidden
    ,
    /// Not found. The user doesn't have any permissions to client or the client does not exist.
    NotFound
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum UpdateClientResponse {
    /// Success. The client was updated
    Success
    (String)
    ,
    /// Unauthorized. The request JWT found in the Authorization header is no longer valid.
    Unauthorized
    ,
    /// Forbidden. The user doesn't have permission to update the client.
    Forbidden
    ,
    /// Not found. The user doesn't have permission to the account or the client does not exist.
    NotFound
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum CreateTenantResponse {
    /// Success. Tenant created
    Success
    (String)
    ,
    /// Unauthorized. The request JWT found in the Authorization header is no longer valid.
    Unauthorized
    ,
    /// Forbidden. The user doesn't have permission to create tenants.
    Forbidden
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum DeleteTenantResponse {
    /// Success. Tenant deleted
    Success
    ,
    /// Unauthorized. The request JWT found in the Authorization header is no longer valid.
    Unauthorized
    ,
    /// Forbidden. The user doesn't have permission to delete tenant.
    Forbidden
    ,
    /// Not found. The tenant does not exist.
    NotFound
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum GetTenantResponse {
    /// Success.
    Success
    (String)
    ,
    /// Unauthorized. The request JWT found in the Authorization header is no longer valid.
    Unauthorized
    ,
    /// Forbidden. The user doesn't have permission to get the tenant.
    Forbidden
    ,
    /// Not found. The tenant does not exist.
    NotFound
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum GetTenantsResponse {
    /// Success.
    Success
    (String)
    ,
    /// Unauthorized. The request JWT found in the Authorization header is no longer valid.
    Unauthorized
    ,
    /// Forbidden. The user doesn't have permission to fetch account tenants, but has other account permissions.
    Forbidden
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum UpdateTenantResponse {
    /// Success. Tenant updated
    Success
    (String)
    ,
    /// Unauthorized. The request JWT found in the Authorization header is no longer valid.
    Unauthorized
    ,
    /// Forbidden. The user doesn't have permission to update tenant.
    Forbidden
    ,
    /// Not found. The tenant does not exist.
    NotFound
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum AuthorizeUserResponse {
    /// Success. The user has permissions
    Success
    ,
    /// Unauthorized. The request JWT found in the Authorization header is no longer valid.
    Unauthorized
    ,
    /// Forbidden. The requestor of the authorization check doesn't have the required permission to check the user's authorization.
    Forbidden
    ,
    /// Not found. The user doesn't have any permissions to the resource including the one requested.
    NotFound
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum GetUserPermissionsForResourceResponse {
    /// Success. The user has permissions
    Success
    (String)
    ,
    /// Unauthorized. The request JWT found in the Authorization header is no longer valid.
    Unauthorized
    ,
    /// Not found. The user doesn't have any permissions to the resource.
    NotFound
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum GetUserResourcesResponse {
    /// Success.
    Success
    (String)
    ,
    /// Unauthorized. The request JWT found in the Authorization header is no longer valid.
    Unauthorized
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum GetUserRolesForResourceResponse {
    /// Success. The user has roles
    Success
    (String)
    ,
    /// Unauthorized. The request JWT found in the Authorization header is no longer valid.
    Unauthorized
    ,
    /// Not found. The user doesn't have any permissions to the resource.
    NotFound
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum DeleteUserResponse {
    /// Success. User will be deleted.
    Success
    ,
    /// Unauthorized. The request JWT found in the Authorization header is no longer valid.
    Unauthorized
    ,
    /// Forbidden. The user doesn't have permission to delete users.
    Forbidden
    ,
    /// Not found. The user does not exist.
    NotFound
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum GetUserResponse {
    /// Success.
    Success
    (String)
    ,
    /// Unauthorized. The request JWT found in the Authorization header is no longer valid.
    Unauthorized
    ,
    /// Forbidden. The user doesn't have permission to get user data.
    Forbidden
    ,
    /// Not found. The user does not exist.
    NotFound
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum GetUsersResponse {
    /// Success.
    Success
    (String)
    ,
    /// Unauthorized. The request JWT found in the Authorization header is no longer valid.
    Unauthorized
    ,
    /// Forbidden. The user doesn't have permission to fetch users for the specified, but has other account permissions
    Forbidden
}

/// API
#[async_trait]
#[allow(clippy::too_many_arguments, clippy::ptr_arg)]
pub trait Api<C: Send + Sync> {
    fn poll_ready(&self, _cx: &mut Context) -> Poll<Result<(), Box<dyn Error + Send + Sync + 'static>>> {
        Poll::Ready(Ok(()))
    }

    /// Create resource Claim
    async fn create_claim(
        &self,
        claim_request: ClaimRequest,
        context: &C) -> Result<CreateClaimResponse, ApiError>;

    /// Create user invite
    async fn create_invite(
        &self,
        invite: Invite,
        context: &C) -> Result<CreateInviteResponse, ApiError>;

    /// Create access record
    async fn create_record(
        &self,
        access_record: AccessRecord,
        context: &C) -> Result<CreateRecordResponse, ApiError>;

    /// Create access request
    async fn create_request(
        &self,
        access_request: AccessRequest,
        context: &C) -> Result<CreateRequestResponse, ApiError>;

    /// Delete invite
    async fn delete_invite(
        &self,
        invite_id: String,
        context: &C) -> Result<DeleteInviteResponse, ApiError>;

    /// Deletes access record
    async fn delete_record(
        &self,
        record_id: String,
        context: &C) -> Result<DeleteRecordResponse, ApiError>;

    /// Deletes access request
    async fn delete_request(
        &self,
        request_id: String,
        context: &C) -> Result<DeleteRequestResponse, ApiError>;

    /// Retrieve access record
    async fn get_record(
        &self,
        record_id: String,
        context: &C) -> Result<GetRecordResponse, ApiError>;

    /// List access records
    async fn get_records(
        &self,
        limit: Option<i32>,
        cursor: Option<String>,
        filter: Option<String>,
        status: Option<String>,
        context: &C) -> Result<GetRecordsResponse, ApiError>;

    /// Retrieve access request
    async fn get_request(
        &self,
        request_id: String,
        context: &C) -> Result<GetRequestResponse, ApiError>;

    /// List access requests
    async fn get_requests(
        &self,
        limit: Option<i32>,
        cursor: Option<String>,
        status: Option<String>,
        context: &C) -> Result<GetRequestsResponse, ApiError>;

    /// Approve or deny access request
    async fn respond_to_access_request(
        &self,
        request_id: String,
        access_request_response: AccessRequestResponse,
        context: &C) -> Result<RespondToAccessRequestResponse, ApiError>;

    /// Accept invite
    async fn respond_to_invite(
        &self,
        invite_id: String,
        context: &C) -> Result<RespondToInviteResponse, ApiError>;

    /// Update access record
    async fn update_record(
        &self,
        record_id: String,
        access_record: AccessRecord,
        if_unmodified_since: Option<String>,
        context: &C) -> Result<UpdateRecordResponse, ApiError>;

    /// Link external provider
    async fn delegate_authentication(
        &self,
        identity_request: IdentityRequest,
        context: &C) -> Result<DelegateAuthenticationResponse, ApiError>;

    /// Retrieve account information
    async fn get_account(
        &self,
        account_id: String,
        context: &C) -> Result<GetAccountResponse, ApiError>;

    /// List linked external providers
    async fn get_account_identities(
        &self,
        context: &C) -> Result<GetAccountIdentitiesResponse, ApiError>;

    /// List user Authress accounts
    async fn get_accounts(
        &self,
        earliest_cache_time: Option<chrono::DateTime::<chrono::Utc>>,
        context: &C) -> Result<GetAccountsResponse, ApiError>;

    /// Log user into third-party application
    async fn delegate_user_login(
        &self,
        application_id: String,
        user_id: String,
        context: &C) -> Result<DelegateUserLoginResponse, ApiError>;

    /// Create SSO connection
    async fn create_connection(
        &self,
        connection: Connection,
        context: &C) -> Result<CreateConnectionResponse, ApiError>;

    /// Delete SSO connection
    async fn delete_connection(
        &self,
        connection_id: String,
        context: &C) -> Result<DeleteConnectionResponse, ApiError>;

    /// Retrieve SSO connection
    async fn get_connection(
        &self,
        connection_id: String,
        context: &C) -> Result<GetConnectionResponse, ApiError>;

    /// Retrieve user connection credentials
    async fn get_connection_credentials(
        &self,
        connection_id: String,
        user_id: String,
        context: &C) -> Result<GetConnectionCredentialsResponse, ApiError>;

    /// List SSO connections
    async fn get_connections(
        &self,
        context: &C) -> Result<GetConnectionsResponse, ApiError>;

    /// Update SSO connection
    async fn update_connection(
        &self,
        connection_id: String,
        connection: Connection,
        context: &C) -> Result<UpdateConnectionResponse, ApiError>;

    /// Create extension
    async fn create_extension(
        &self,
        extension: Extension,
        context: &C) -> Result<CreateExtensionResponse, ApiError>;

    /// Delete extension
    async fn delete_extension(
        &self,
        extension_id: String,
        context: &C) -> Result<DeleteExtensionResponse, ApiError>;

    /// Retrieve extension
    async fn get_extension(
        &self,
        extension_id: String,
        context: &C) -> Result<GetExtensionResponse, ApiError>;

    /// List extensions
    async fn get_extensions(
        &self,
        context: &C) -> Result<GetExtensionsResponse, ApiError>;

    /// OAuth Authorize
    async fn login(
        &self,
        client_id: String,
        code_challenge: String,
        redirect_uri: String,
        code_challenge_method: Option<String>,
        context: &C) -> Result<LoginResponse, ApiError>;

    /// OAuth Token
    async fn request_token(
        &self,
        o_auth_token_request: OAuthTokenRequest,
        context: &C) -> Result<RequestTokenResponse, ApiError>;

    /// Update extension
    async fn update_extension(
        &self,
        extension_id: String,
        extension: Extension,
        context: &C) -> Result<UpdateExtensionResponse, ApiError>;

    /// Create group
    async fn create_group(
        &self,
        group: Group,
        context: &C) -> Result<CreateGroupResponse, ApiError>;

    /// Deletes group
    async fn delete_group(
        &self,
        group_id: String,
        context: &C) -> Result<DeleteGroupResponse, ApiError>;

    /// Retrieve group
    async fn get_group(
        &self,
        group_id: String,
        context: &C) -> Result<GetGroupResponse, ApiError>;

    /// List groups
    async fn get_groups(
        &self,
        limit: Option<i32>,
        cursor: Option<String>,
        filter: Option<String>,
        context: &C) -> Result<GetGroupsResponse, ApiError>;

    /// Update a group
    async fn update_group(
        &self,
        group_id: String,
        group: Group,
        context: &C) -> Result<UpdateGroupResponse, ApiError>;

    /// Retrieve resource configuration
    async fn get_permissioned_resource(
        &self,
        resource_uri: String,
        context: &C) -> Result<GetPermissionedResourceResponse, ApiError>;

    /// List all resource configurations
    async fn get_permissioned_resources(
        &self,
        context: &C) -> Result<GetPermissionedResourcesResponse, ApiError>;

    /// List users with resource access
    async fn get_resource_users(
        &self,
        resource_uri: String,
        limit: Option<i32>,
        cursor: Option<String>,
        context: &C) -> Result<GetResourceUsersResponse, ApiError>;

    /// Update resource configuration
    async fn update_permissioned_resource(
        &self,
        resource_uri: String,
        permissioned_resource: PermissionedResource,
        context: &C) -> Result<UpdatePermissionedResourceResponse, ApiError>;

    /// Create role
    async fn create_role(
        &self,
        role: Role,
        context: &C) -> Result<CreateRoleResponse, ApiError>;

    /// Deletes role
    async fn delete_role(
        &self,
        role_id: String,
        context: &C) -> Result<DeleteRoleResponse, ApiError>;

    /// Retrieve role
    async fn get_role(
        &self,
        role_id: String,
        context: &C) -> Result<GetRoleResponse, ApiError>;

    /// List roles
    async fn get_roles(
        &self,
        context: &C) -> Result<GetRolesResponse, ApiError>;

    /// Update role
    async fn update_role(
        &self,
        role_id: String,
        role: Role,
        context: &C) -> Result<UpdateRoleResponse, ApiError>;

    /// Create service client
    async fn create_client(
        &self,
        client: Client,
        context: &C) -> Result<CreateClientResponse, ApiError>;

    /// Delete service client access key
    async fn delete_access_key(
        &self,
        client_id: String,
        key_id: String,
        context: &C) -> Result<DeleteAccessKeyResponse, ApiError>;

    /// Delete service client
    async fn delete_client(
        &self,
        client_id: String,
        context: &C) -> Result<DeleteClientResponse, ApiError>;

    /// Retrieve service client
    async fn get_client(
        &self,
        client_id: String,
        context: &C) -> Result<GetClientResponse, ApiError>;

    /// List service clients
    async fn get_clients(
        &self,
        limit: Option<i32>,
        cursor: Option<String>,
        context: &C) -> Result<GetClientsResponse, ApiError>;

    /// Generate service client access key
    async fn request_access_key(
        &self,
        client_id: String,
        context: &C) -> Result<RequestAccessKeyResponse, ApiError>;

    /// Update service client
    async fn update_client(
        &self,
        client_id: String,
        client: Client,
        context: &C) -> Result<UpdateClientResponse, ApiError>;

    /// Create tenant
    async fn create_tenant(
        &self,
        tenant: Tenant,
        context: &C) -> Result<CreateTenantResponse, ApiError>;

    /// Delete tenant
    async fn delete_tenant(
        &self,
        tenant_id: String,
        context: &C) -> Result<DeleteTenantResponse, ApiError>;

    /// Retrieve tenant
    async fn get_tenant(
        &self,
        tenant_id: String,
        context: &C) -> Result<GetTenantResponse, ApiError>;

    /// List tenants
    async fn get_tenants(
        &self,
        context: &C) -> Result<GetTenantsResponse, ApiError>;

    /// Update tenant
    async fn update_tenant(
        &self,
        tenant_id: String,
        tenant: Tenant,
        context: &C) -> Result<UpdateTenantResponse, ApiError>;

    /// Verify user authorization
    async fn authorize_user(
        &self,
        user_id: String,
        resource_uri: String,
        permission: String,
        context: &C) -> Result<AuthorizeUserResponse, ApiError>;

    /// Get user permissions for resource
    async fn get_user_permissions_for_resource(
        &self,
        user_id: String,
        resource_uri: String,
        context: &C) -> Result<GetUserPermissionsForResourceResponse, ApiError>;

    /// List user resources
    async fn get_user_resources(
        &self,
        user_id: String,
        resource_uri: Option<String>,
        collection_configuration: Option<String>,
        permissions: Option<String>,
        limit: Option<i32>,
        cursor: Option<String>,
        context: &C) -> Result<GetUserResourcesResponse, ApiError>;

    /// Get user roles for resource
    async fn get_user_roles_for_resource(
        &self,
        user_id: String,
        resource_uri: String,
        context: &C) -> Result<GetUserRolesForResourceResponse, ApiError>;

    /// Delete a user
    async fn delete_user(
        &self,
        user_id: String,
        context: &C) -> Result<DeleteUserResponse, ApiError>;

    /// Retrieve a user
    async fn get_user(
        &self,
        user_id: String,
        context: &C) -> Result<GetUserResponse, ApiError>;

    /// List users
    async fn get_users(
        &self,
        limit: Option<i32>,
        cursor: Option<String>,
        filter: Option<String>,
        tenant_id: Option<String>,
        context: &C) -> Result<GetUsersResponse, ApiError>;

}

/// API where `Context` isn't passed on every API call
#[async_trait]
#[allow(clippy::too_many_arguments, clippy::ptr_arg)]
pub trait ApiNoContext<C: Send + Sync> {

    fn poll_ready(&self, _cx: &mut Context) -> Poll<Result<(), Box<dyn Error + Send + Sync + 'static>>>;

    fn context(&self) -> &C;

    /// Create resource Claim
    async fn create_claim(
        &self,
        claim_request: ClaimRequest,
        ) -> Result<CreateClaimResponse, ApiError>;

    /// Create user invite
    async fn create_invite(
        &self,
        invite: Invite,
        ) -> Result<CreateInviteResponse, ApiError>;

    /// Create access record
    async fn create_record(
        &self,
        access_record: AccessRecord,
        ) -> Result<CreateRecordResponse, ApiError>;

    /// Create access request
    async fn create_request(
        &self,
        access_request: AccessRequest,
        ) -> Result<CreateRequestResponse, ApiError>;

    /// Delete invite
    async fn delete_invite(
        &self,
        invite_id: String,
        ) -> Result<DeleteInviteResponse, ApiError>;

    /// Deletes access record
    async fn delete_record(
        &self,
        record_id: String,
        ) -> Result<DeleteRecordResponse, ApiError>;

    /// Deletes access request
    async fn delete_request(
        &self,
        request_id: String,
        ) -> Result<DeleteRequestResponse, ApiError>;

    /// Retrieve access record
    async fn get_record(
        &self,
        record_id: String,
        ) -> Result<GetRecordResponse, ApiError>;

    /// List access records
    async fn get_records(
        &self,
        limit: Option<i32>,
        cursor: Option<String>,
        filter: Option<String>,
        status: Option<String>,
        ) -> Result<GetRecordsResponse, ApiError>;

    /// Retrieve access request
    async fn get_request(
        &self,
        request_id: String,
        ) -> Result<GetRequestResponse, ApiError>;

    /// List access requests
    async fn get_requests(
        &self,
        limit: Option<i32>,
        cursor: Option<String>,
        status: Option<String>,
        ) -> Result<GetRequestsResponse, ApiError>;

    /// Approve or deny access request
    async fn respond_to_access_request(
        &self,
        request_id: String,
        access_request_response: AccessRequestResponse,
        ) -> Result<RespondToAccessRequestResponse, ApiError>;

    /// Accept invite
    async fn respond_to_invite(
        &self,
        invite_id: String,
        ) -> Result<RespondToInviteResponse, ApiError>;

    /// Update access record
    async fn update_record(
        &self,
        record_id: String,
        access_record: AccessRecord,
        if_unmodified_since: Option<String>,
        ) -> Result<UpdateRecordResponse, ApiError>;

    /// Link external provider
    async fn delegate_authentication(
        &self,
        identity_request: IdentityRequest,
        ) -> Result<DelegateAuthenticationResponse, ApiError>;

    /// Retrieve account information
    async fn get_account(
        &self,
        account_id: String,
        ) -> Result<GetAccountResponse, ApiError>;

    /// List linked external providers
    async fn get_account_identities(
        &self,
        ) -> Result<GetAccountIdentitiesResponse, ApiError>;

    /// List user Authress accounts
    async fn get_accounts(
        &self,
        earliest_cache_time: Option<chrono::DateTime::<chrono::Utc>>,
        ) -> Result<GetAccountsResponse, ApiError>;

    /// Log user into third-party application
    async fn delegate_user_login(
        &self,
        application_id: String,
        user_id: String,
        ) -> Result<DelegateUserLoginResponse, ApiError>;

    /// Create SSO connection
    async fn create_connection(
        &self,
        connection: Connection,
        ) -> Result<CreateConnectionResponse, ApiError>;

    /// Delete SSO connection
    async fn delete_connection(
        &self,
        connection_id: String,
        ) -> Result<DeleteConnectionResponse, ApiError>;

    /// Retrieve SSO connection
    async fn get_connection(
        &self,
        connection_id: String,
        ) -> Result<GetConnectionResponse, ApiError>;

    /// Retrieve user connection credentials
    async fn get_connection_credentials(
        &self,
        connection_id: String,
        user_id: String,
        ) -> Result<GetConnectionCredentialsResponse, ApiError>;

    /// List SSO connections
    async fn get_connections(
        &self,
        ) -> Result<GetConnectionsResponse, ApiError>;

    /// Update SSO connection
    async fn update_connection(
        &self,
        connection_id: String,
        connection: Connection,
        ) -> Result<UpdateConnectionResponse, ApiError>;

    /// Create extension
    async fn create_extension(
        &self,
        extension: Extension,
        ) -> Result<CreateExtensionResponse, ApiError>;

    /// Delete extension
    async fn delete_extension(
        &self,
        extension_id: String,
        ) -> Result<DeleteExtensionResponse, ApiError>;

    /// Retrieve extension
    async fn get_extension(
        &self,
        extension_id: String,
        ) -> Result<GetExtensionResponse, ApiError>;

    /// List extensions
    async fn get_extensions(
        &self,
        ) -> Result<GetExtensionsResponse, ApiError>;

    /// OAuth Authorize
    async fn login(
        &self,
        client_id: String,
        code_challenge: String,
        redirect_uri: String,
        code_challenge_method: Option<String>,
        ) -> Result<LoginResponse, ApiError>;

    /// OAuth Token
    async fn request_token(
        &self,
        o_auth_token_request: OAuthTokenRequest,
        ) -> Result<RequestTokenResponse, ApiError>;

    /// Update extension
    async fn update_extension(
        &self,
        extension_id: String,
        extension: Extension,
        ) -> Result<UpdateExtensionResponse, ApiError>;

    /// Create group
    async fn create_group(
        &self,
        group: Group,
        ) -> Result<CreateGroupResponse, ApiError>;

    /// Deletes group
    async fn delete_group(
        &self,
        group_id: String,
        ) -> Result<DeleteGroupResponse, ApiError>;

    /// Retrieve group
    async fn get_group(
        &self,
        group_id: String,
        ) -> Result<GetGroupResponse, ApiError>;

    /// List groups
    async fn get_groups(
        &self,
        limit: Option<i32>,
        cursor: Option<String>,
        filter: Option<String>,
        ) -> Result<GetGroupsResponse, ApiError>;

    /// Update a group
    async fn update_group(
        &self,
        group_id: String,
        group: Group,
        ) -> Result<UpdateGroupResponse, ApiError>;

    /// Retrieve resource configuration
    async fn get_permissioned_resource(
        &self,
        resource_uri: String,
        ) -> Result<GetPermissionedResourceResponse, ApiError>;

    /// List all resource configurations
    async fn get_permissioned_resources(
        &self,
        ) -> Result<GetPermissionedResourcesResponse, ApiError>;

    /// List users with resource access
    async fn get_resource_users(
        &self,
        resource_uri: String,
        limit: Option<i32>,
        cursor: Option<String>,
        ) -> Result<GetResourceUsersResponse, ApiError>;

    /// Update resource configuration
    async fn update_permissioned_resource(
        &self,
        resource_uri: String,
        permissioned_resource: PermissionedResource,
        ) -> Result<UpdatePermissionedResourceResponse, ApiError>;

    /// Create role
    async fn create_role(
        &self,
        role: Role,
        ) -> Result<CreateRoleResponse, ApiError>;

    /// Deletes role
    async fn delete_role(
        &self,
        role_id: String,
        ) -> Result<DeleteRoleResponse, ApiError>;

    /// Retrieve role
    async fn get_role(
        &self,
        role_id: String,
        ) -> Result<GetRoleResponse, ApiError>;

    /// List roles
    async fn get_roles(
        &self,
        ) -> Result<GetRolesResponse, ApiError>;

    /// Update role
    async fn update_role(
        &self,
        role_id: String,
        role: Role,
        ) -> Result<UpdateRoleResponse, ApiError>;

    /// Create service client
    async fn create_client(
        &self,
        client: Client,
        ) -> Result<CreateClientResponse, ApiError>;

    /// Delete service client access key
    async fn delete_access_key(
        &self,
        client_id: String,
        key_id: String,
        ) -> Result<DeleteAccessKeyResponse, ApiError>;

    /// Delete service client
    async fn delete_client(
        &self,
        client_id: String,
        ) -> Result<DeleteClientResponse, ApiError>;

    /// Retrieve service client
    async fn get_client(
        &self,
        client_id: String,
        ) -> Result<GetClientResponse, ApiError>;

    /// List service clients
    async fn get_clients(
        &self,
        limit: Option<i32>,
        cursor: Option<String>,
        ) -> Result<GetClientsResponse, ApiError>;

    /// Generate service client access key
    async fn request_access_key(
        &self,
        client_id: String,
        ) -> Result<RequestAccessKeyResponse, ApiError>;

    /// Update service client
    async fn update_client(
        &self,
        client_id: String,
        client: Client,
        ) -> Result<UpdateClientResponse, ApiError>;

    /// Create tenant
    async fn create_tenant(
        &self,
        tenant: Tenant,
        ) -> Result<CreateTenantResponse, ApiError>;

    /// Delete tenant
    async fn delete_tenant(
        &self,
        tenant_id: String,
        ) -> Result<DeleteTenantResponse, ApiError>;

    /// Retrieve tenant
    async fn get_tenant(
        &self,
        tenant_id: String,
        ) -> Result<GetTenantResponse, ApiError>;

    /// List tenants
    async fn get_tenants(
        &self,
        ) -> Result<GetTenantsResponse, ApiError>;

    /// Update tenant
    async fn update_tenant(
        &self,
        tenant_id: String,
        tenant: Tenant,
        ) -> Result<UpdateTenantResponse, ApiError>;

    /// Verify user authorization
    async fn authorize_user(
        &self,
        user_id: String,
        resource_uri: String,
        permission: String,
        ) -> Result<AuthorizeUserResponse, ApiError>;

    /// Get user permissions for resource
    async fn get_user_permissions_for_resource(
        &self,
        user_id: String,
        resource_uri: String,
        ) -> Result<GetUserPermissionsForResourceResponse, ApiError>;

    /// List user resources
    async fn get_user_resources(
        &self,
        user_id: String,
        resource_uri: Option<String>,
        collection_configuration: Option<String>,
        permissions: Option<String>,
        limit: Option<i32>,
        cursor: Option<String>,
        ) -> Result<GetUserResourcesResponse, ApiError>;

    /// Get user roles for resource
    async fn get_user_roles_for_resource(
        &self,
        user_id: String,
        resource_uri: String,
        ) -> Result<GetUserRolesForResourceResponse, ApiError>;

    /// Delete a user
    async fn delete_user(
        &self,
        user_id: String,
        ) -> Result<DeleteUserResponse, ApiError>;

    /// Retrieve a user
    async fn get_user(
        &self,
        user_id: String,
        ) -> Result<GetUserResponse, ApiError>;

    /// List users
    async fn get_users(
        &self,
        limit: Option<i32>,
        cursor: Option<String>,
        filter: Option<String>,
        tenant_id: Option<String>,
        ) -> Result<GetUsersResponse, ApiError>;

}

/// Trait to extend an API to make it easy to bind it to a context.
// pub trait ContextWrapperExt<C: Send + Sync> where Self: Sized
// {
//     /// Binds this API to a context.
//     fn with_context(self, context: C) -> ContextWrapper<Self, C>;
// }

// impl<T: Api<C> + Send + Sync, C: Clone + Send + Sync> ContextWrapperExt<C> for T {
//     fn with_context(self: T, context: C) -> ContextWrapper<T, C> {
//          ContextWrapper::<T, C>::new(self, context)
//     }
// }

// #[async_trait]
// impl<T: Api<C> + Send + Sync, C: Clone + Send + Sync> ApiNoContext<C> for ContextWrapper<T, C> {
//     fn poll_ready(&self, cx: &mut Context) -> Poll<Result<(), ServiceError>> {
//         self.api().poll_ready(cx)
//     }

//     fn context(&self) -> &C {
//         ContextWrapper::context(self)
//     }

//     /// Create resource Claim
//     async fn create_claim(
//         &self,
//         claim_request: ClaimRequest,
//         ) -> Result<CreateClaimResponse, ApiError>
//     {
//         let context = self.context().clone();
//         self.api().create_claim(claim_request, &context).await
//     }

//     /// Create user invite
//     async fn create_invite(
//         &self,
//         invite: Invite,
//         ) -> Result<CreateInviteResponse, ApiError>
//     {
//         let context = self.context().clone();
//         self.api().create_invite(invite, &context).await
//     }

//     /// Create access record
//     async fn create_record(
//         &self,
//         access_record: AccessRecord,
//         ) -> Result<CreateRecordResponse, ApiError>
//     {
//         let context = self.context().clone();
//         self.api().create_record(access_record, &context).await
//     }

//     /// Create access request
//     async fn create_request(
//         &self,
//         access_request: AccessRequest,
//         ) -> Result<CreateRequestResponse, ApiError>
//     {
//         let context = self.context().clone();
//         self.api().create_request(access_request, &context).await
//     }

//     /// Delete invite
//     async fn delete_invite(
//         &self,
//         invite_id: String,
//         ) -> Result<DeleteInviteResponse, ApiError>
//     {
//         let context = self.context().clone();
//         self.api().delete_invite(invite_id, &context).await
//     }

//     /// Deletes access record
//     async fn delete_record(
//         &self,
//         record_id: String,
//         ) -> Result<DeleteRecordResponse, ApiError>
//     {
//         let context = self.context().clone();
//         self.api().delete_record(record_id, &context).await
//     }

//     /// Deletes access request
//     async fn delete_request(
//         &self,
//         request_id: String,
//         ) -> Result<DeleteRequestResponse, ApiError>
//     {
//         let context = self.context().clone();
//         self.api().delete_request(request_id, &context).await
//     }

//     /// Retrieve access record
//     async fn get_record(
//         &self,
//         record_id: String,
//         ) -> Result<GetRecordResponse, ApiError>
//     {
//         let context = self.context().clone();
//         self.api().get_record(record_id, &context).await
//     }

//     /// List access records
//     async fn get_records(
//         &self,
//         limit: Option<i32>,
//         cursor: Option<String>,
//         filter: Option<String>,
//         status: Option<String>,
//         ) -> Result<GetRecordsResponse, ApiError>
//     {
//         let context = self.context().clone();
//         self.api().get_records(limit, cursor, filter, status, &context).await
//     }

//     /// Retrieve access request
//     async fn get_request(
//         &self,
//         request_id: String,
//         ) -> Result<GetRequestResponse, ApiError>
//     {
//         let context = self.context().clone();
//         self.api().get_request(request_id, &context).await
//     }

//     /// List access requests
//     async fn get_requests(
//         &self,
//         limit: Option<i32>,
//         cursor: Option<String>,
//         status: Option<String>,
//         ) -> Result<GetRequestsResponse, ApiError>
//     {
//         let context = self.context().clone();
//         self.api().get_requests(limit, cursor, status, &context).await
//     }

//     /// Approve or deny access request
//     async fn respond_to_access_request(
//         &self,
//         request_id: String,
//         access_request_response: AccessRequestResponse,
//         ) -> Result<RespondToAccessRequestResponse, ApiError>
//     {
//         let context = self.context().clone();
//         self.api().respond_to_access_request(request_id, access_request_response, &context).await
//     }

//     /// Accept invite
//     async fn respond_to_invite(
//         &self,
//         invite_id: String,
//         ) -> Result<RespondToInviteResponse, ApiError>
//     {
//         let context = self.context().clone();
//         self.api().respond_to_invite(invite_id, &context).await
//     }

//     /// Update access record
//     async fn update_record(
//         &self,
//         record_id: String,
//         access_record: AccessRecord,
//         if_unmodified_since: Option<String>,
//         ) -> Result<UpdateRecordResponse, ApiError>
//     {
//         let context = self.context().clone();
//         self.api().update_record(record_id, access_record, if_unmodified_since, &context).await
//     }

//     /// Link external provider
//     async fn delegate_authentication(
//         &self,
//         identity_request: IdentityRequest,
//         ) -> Result<DelegateAuthenticationResponse, ApiError>
//     {
//         let context = self.context().clone();
//         self.api().delegate_authentication(identity_request, &context).await
//     }

//     /// Retrieve account information
//     async fn get_account(
//         &self,
//         account_id: String,
//         ) -> Result<GetAccountResponse, ApiError>
//     {
//         let context = self.context().clone();
//         self.api().get_account(account_id, &context).await
//     }

//     /// List linked external providers
//     async fn get_account_identities(
//         &self,
//         ) -> Result<GetAccountIdentitiesResponse, ApiError>
//     {
//         let context = self.context().clone();
//         self.api().get_account_identities(&context).await
//     }

//     /// List user Authress accounts
//     async fn get_accounts(
//         &self,
//         earliest_cache_time: Option<chrono::DateTime::<chrono::Utc>>,
//         ) -> Result<GetAccountsResponse, ApiError>
//     {
//         let context = self.context().clone();
//         self.api().get_accounts(earliest_cache_time, &context).await
//     }

//     /// Log user into third-party application
//     async fn delegate_user_login(
//         &self,
//         application_id: String,
//         user_id: String,
//         ) -> Result<DelegateUserLoginResponse, ApiError>
//     {
//         let context = self.context().clone();
//         self.api().delegate_user_login(application_id, user_id, &context).await
//     }

//     /// Create SSO connection
//     async fn create_connection(
//         &self,
//         connection: Connection,
//         ) -> Result<CreateConnectionResponse, ApiError>
//     {
//         let context = self.context().clone();
//         self.api().create_connection(connection, &context).await
//     }

//     /// Delete SSO connection
//     async fn delete_connection(
//         &self,
//         connection_id: String,
//         ) -> Result<DeleteConnectionResponse, ApiError>
//     {
//         let context = self.context().clone();
//         self.api().delete_connection(connection_id, &context).await
//     }

//     /// Retrieve SSO connection
//     async fn get_connection(
//         &self,
//         connection_id: String,
//         ) -> Result<GetConnectionResponse, ApiError>
//     {
//         let context = self.context().clone();
//         self.api().get_connection(connection_id, &context).await
//     }

//     /// Retrieve user connection credentials
//     async fn get_connection_credentials(
//         &self,
//         connection_id: String,
//         user_id: String,
//         ) -> Result<GetConnectionCredentialsResponse, ApiError>
//     {
//         let context = self.context().clone();
//         self.api().get_connection_credentials(connection_id, user_id, &context).await
//     }

//     /// List SSO connections
//     async fn get_connections(
//         &self,
//         ) -> Result<GetConnectionsResponse, ApiError>
//     {
//         let context = self.context().clone();
//         self.api().get_connections(&context).await
//     }

//     /// Update SSO connection
//     async fn update_connection(
//         &self,
//         connection_id: String,
//         connection: Connection,
//         ) -> Result<UpdateConnectionResponse, ApiError>
//     {
//         let context = self.context().clone();
//         self.api().update_connection(connection_id, connection, &context).await
//     }

//     /// Create extension
//     async fn create_extension(
//         &self,
//         extension: Extension,
//         ) -> Result<CreateExtensionResponse, ApiError>
//     {
//         let context = self.context().clone();
//         self.api().create_extension(extension, &context).await
//     }

//     /// Delete extension
//     async fn delete_extension(
//         &self,
//         extension_id: String,
//         ) -> Result<DeleteExtensionResponse, ApiError>
//     {
//         let context = self.context().clone();
//         self.api().delete_extension(extension_id, &context).await
//     }

//     /// Retrieve extension
//     async fn get_extension(
//         &self,
//         extension_id: String,
//         ) -> Result<GetExtensionResponse, ApiError>
//     {
//         let context = self.context().clone();
//         self.api().get_extension(extension_id, &context).await
//     }

//     /// List extensions
//     async fn get_extensions(
//         &self,
//         ) -> Result<GetExtensionsResponse, ApiError>
//     {
//         let context = self.context().clone();
//         self.api().get_extensions(&context).await
//     }

//     /// OAuth Authorize
//     async fn login(
//         &self,
//         client_id: String,
//         code_challenge: String,
//         redirect_uri: String,
//         code_challenge_method: Option<String>,
//         ) -> Result<LoginResponse, ApiError>
//     {
//         let context = self.context().clone();
//         self.api().login(client_id, code_challenge, redirect_uri, code_challenge_method, &context).await
//     }

//     /// OAuth Token
//     async fn request_token(
//         &self,
//         o_auth_token_request: OAuthTokenRequest,
//         ) -> Result<RequestTokenResponse, ApiError>
//     {
//         let context = self.context().clone();
//         self.api().request_token(o_auth_token_request, &context).await
//     }

//     /// Update extension
//     async fn update_extension(
//         &self,
//         extension_id: String,
//         extension: Extension,
//         ) -> Result<UpdateExtensionResponse, ApiError>
//     {
//         let context = self.context().clone();
//         self.api().update_extension(extension_id, extension, &context).await
//     }

//     /// Create group
//     async fn create_group(
//         &self,
//         group: Group,
//         ) -> Result<CreateGroupResponse, ApiError>
//     {
//         let context = self.context().clone();
//         self.api().create_group(group, &context).await
//     }

//     /// Deletes group
//     async fn delete_group(
//         &self,
//         group_id: String,
//         ) -> Result<DeleteGroupResponse, ApiError>
//     {
//         let context = self.context().clone();
//         self.api().delete_group(group_id, &context).await
//     }

//     /// Retrieve group
//     async fn get_group(
//         &self,
//         group_id: String,
//         ) -> Result<GetGroupResponse, ApiError>
//     {
//         let context = self.context().clone();
//         self.api().get_group(group_id, &context).await
//     }

//     /// List groups
//     async fn get_groups(
//         &self,
//         limit: Option<i32>,
//         cursor: Option<String>,
//         filter: Option<String>,
//         ) -> Result<GetGroupsResponse, ApiError>
//     {
//         let context = self.context().clone();
//         self.api().get_groups(limit, cursor, filter, &context).await
//     }

//     /// Update a group
//     async fn update_group(
//         &self,
//         group_id: String,
//         group: Group,
//         ) -> Result<UpdateGroupResponse, ApiError>
//     {
//         let context = self.context().clone();
//         self.api().update_group(group_id, group, &context).await
//     }

//     /// Retrieve resource configuration
//     async fn get_permissioned_resource(
//         &self,
//         resource_uri: String,
//         ) -> Result<GetPermissionedResourceResponse, ApiError>
//     {
//         let context = self.context().clone();
//         self.api().get_permissioned_resource(resource_uri, &context).await
//     }

//     /// List all resource configurations
//     async fn get_permissioned_resources(
//         &self,
//         ) -> Result<GetPermissionedResourcesResponse, ApiError>
//     {
//         let context = self.context().clone();
//         self.api().get_permissioned_resources(&context).await
//     }

//     /// List users with resource access
//     async fn get_resource_users(
//         &self,
//         resource_uri: String,
//         limit: Option<i32>,
//         cursor: Option<String>,
//         ) -> Result<GetResourceUsersResponse, ApiError>
//     {
//         let context = self.context().clone();
//         self.api().get_resource_users(resource_uri, limit, cursor, &context).await
//     }

//     /// Update resource configuration
//     async fn update_permissioned_resource(
//         &self,
//         resource_uri: String,
//         permissioned_resource: PermissionedResource,
//         ) -> Result<UpdatePermissionedResourceResponse, ApiError>
//     {
//         let context = self.context().clone();
//         self.api().update_permissioned_resource(resource_uri, permissioned_resource, &context).await
//     }

//     /// Create role
//     async fn create_role(
//         &self,
//         role: Role,
//         ) -> Result<CreateRoleResponse, ApiError>
//     {
//         let context = self.context().clone();
//         self.api().create_role(role, &context).await
//     }

//     /// Deletes role
//     async fn delete_role(
//         &self,
//         role_id: String,
//         ) -> Result<DeleteRoleResponse, ApiError>
//     {
//         let context = self.context().clone();
//         self.api().delete_role(role_id, &context).await
//     }

//     /// Retrieve role
//     async fn get_role(
//         &self,
//         role_id: String,
//         ) -> Result<GetRoleResponse, ApiError>
//     {
//         let context = self.context().clone();
//         self.api().get_role(role_id, &context).await
//     }

//     /// List roles
//     async fn get_roles(
//         &self,
//         ) -> Result<GetRolesResponse, ApiError>
//     {
//         let context = self.context().clone();
//         self.api().get_roles(&context).await
//     }

//     /// Update role
//     async fn update_role(
//         &self,
//         role_id: String,
//         role: Role,
//         ) -> Result<UpdateRoleResponse, ApiError>
//     {
//         let context = self.context().clone();
//         self.api().update_role(role_id, role, &context).await
//     }

//     /// Create service client
//     async fn create_client(
//         &self,
//         client: Client,
//         ) -> Result<CreateClientResponse, ApiError>
//     {
//         let context = self.context().clone();
//         self.api().create_client(client, &context).await
//     }

//     /// Delete service client access key
//     async fn delete_access_key(
//         &self,
//         client_id: String,
//         key_id: String,
//         ) -> Result<DeleteAccessKeyResponse, ApiError>
//     {
//         let context = self.context().clone();
//         self.api().delete_access_key(client_id, key_id, &context).await
//     }

//     /// Delete service client
//     async fn delete_client(
//         &self,
//         client_id: String,
//         ) -> Result<DeleteClientResponse, ApiError>
//     {
//         let context = self.context().clone();
//         self.api().delete_client(client_id, &context).await
//     }

//     /// Retrieve service client
//     async fn get_client(
//         &self,
//         client_id: String,
//         ) -> Result<GetClientResponse, ApiError>
//     {
//         let context = self.context().clone();
//         self.api().get_client(client_id, &context).await
//     }

//     /// List service clients
//     async fn get_clients(
//         &self,
//         limit: Option<i32>,
//         cursor: Option<String>,
//         ) -> Result<GetClientsResponse, ApiError>
//     {
//         let context = self.context().clone();
//         self.api().get_clients(limit, cursor, &context).await
//     }

//     /// Generate service client access key
//     async fn request_access_key(
//         &self,
//         client_id: String,
//         ) -> Result<RequestAccessKeyResponse, ApiError>
//     {
//         let context = self.context().clone();
//         self.api().request_access_key(client_id, &context).await
//     }

//     /// Update service client
//     async fn update_client(
//         &self,
//         client_id: String,
//         client: Client,
//         ) -> Result<UpdateClientResponse, ApiError>
//     {
//         let context = self.context().clone();
//         self.api().update_client(client_id, client, &context).await
//     }

//     /// Create tenant
//     async fn create_tenant(
//         &self,
//         tenant: Tenant,
//         ) -> Result<CreateTenantResponse, ApiError>
//     {
//         let context = self.context().clone();
//         self.api().create_tenant(tenant, &context).await
//     }

//     /// Delete tenant
//     async fn delete_tenant(
//         &self,
//         tenant_id: String,
//         ) -> Result<DeleteTenantResponse, ApiError>
//     {
//         let context = self.context().clone();
//         self.api().delete_tenant(tenant_id, &context).await
//     }

//     /// Retrieve tenant
//     async fn get_tenant(
//         &self,
//         tenant_id: String,
//         ) -> Result<GetTenantResponse, ApiError>
//     {
//         let context = self.context().clone();
//         self.api().get_tenant(tenant_id, &context).await
//     }

//     /// List tenants
//     async fn get_tenants(
//         &self,
//         ) -> Result<GetTenantsResponse, ApiError>
//     {
//         let context = self.context().clone();
//         self.api().get_tenants(&context).await
//     }

//     /// Update tenant
//     async fn update_tenant(
//         &self,
//         tenant_id: String,
//         tenant: Tenant,
//         ) -> Result<UpdateTenantResponse, ApiError>
//     {
//         let context = self.context().clone();
//         self.api().update_tenant(tenant_id, tenant, &context).await
//     }

//     /// Verify user authorization
//     async fn authorize_user(
//         &self,
//         user_id: String,
//         resource_uri: String,
//         permission: String,
//         ) -> Result<AuthorizeUserResponse, ApiError>
//     {
//         let context = self.context().clone();
//         self.api().authorize_user(user_id, resource_uri, permission, &context).await
//     }

//     /// Get user permissions for resource
//     async fn get_user_permissions_for_resource(
//         &self,
//         user_id: String,
//         resource_uri: String,
//         ) -> Result<GetUserPermissionsForResourceResponse, ApiError>
//     {
//         let context = self.context().clone();
//         self.api().get_user_permissions_for_resource(user_id, resource_uri, &context).await
//     }

//     /// List user resources
//     async fn get_user_resources(
//         &self,
//         user_id: String,
//         resource_uri: Option<String>,
//         collection_configuration: Option<String>,
//         permissions: Option<String>,
//         limit: Option<i32>,
//         cursor: Option<String>,
//         ) -> Result<GetUserResourcesResponse, ApiError>
//     {
//         let context = self.context().clone();
//         self.api().get_user_resources(user_id, resource_uri, collection_configuration, permissions, limit, cursor, &context).await
//     }

//     /// Get user roles for resource
//     async fn get_user_roles_for_resource(
//         &self,
//         user_id: String,
//         resource_uri: String,
//         ) -> Result<GetUserRolesForResourceResponse, ApiError>
//     {
//         let context = self.context().clone();
//         self.api().get_user_roles_for_resource(user_id, resource_uri, &context).await
//     }

//     /// Delete a user
//     async fn delete_user(
//         &self,
//         user_id: String,
//         ) -> Result<DeleteUserResponse, ApiError>
//     {
//         let context = self.context().clone();
//         self.api().delete_user(user_id, &context).await
//     }

//     /// Retrieve a user
//     async fn get_user(
//         &self,
//         user_id: String,
//         ) -> Result<GetUserResponse, ApiError>
//     {
//         let context = self.context().clone();
//         self.api().get_user(user_id, &context).await
//     }

//     /// List users
//     async fn get_users(
//         &self,
//         limit: Option<i32>,
//         cursor: Option<String>,
//         filter: Option<String>,
//         tenant_id: Option<String>,
//         ) -> Result<GetUsersResponse, ApiError>
//     {
//         let context = self.context().clone();
//         self.api().get_users(limit, cursor, filter, tenant_id, &context).await
//     }

// }

#[cfg(feature = "server")]
pub mod server;

// Re-export router() as a top-level name
#[cfg(feature = "server")]
pub use self::server::Service;

#[cfg(feature = "server")]
pub mod context;

#[cfg(any(feature = "server"))]
pub(crate) mod header;

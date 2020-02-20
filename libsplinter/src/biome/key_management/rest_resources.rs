// Copyright 2018-2020 Cargill Incorporated
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::sync::Arc;

use crate::actix_web::{web::Payload, Error as ActixError, HttpRequest, HttpResponse};
use crate::protocol;
use crate::rest_api::{
    get_authorization_token, into_bytes, ErrorResponse, Method, ProtocolVersionRangeGuard, Resource,
};

use super::super::rest_api::BiomeRestConfig;
use super::super::secrets::SecretManager;
use super::super::sessions::{validate_token, TokenValidationError};

use super::{
    store::{KeyStore, KeyStoreError},
    Key,
};

#[derive(Deserialize)]
struct NewKey {
    public_key: String,
    encrypted_private_key: String,
    display_name: String,
}

#[derive(Deserialize)]
struct UpdatedKey {
    public_key: String,
    new_display_name: String,
}

/// Defines a REST endpoint for managing keys
pub fn make_key_management_route(
    rest_config: Arc<BiomeRestConfig>,
    key_store: Arc<dyn KeyStore<Key>>,
    secret_manager: Arc<dyn SecretManager>,
) -> Resource {
    Resource::build("/biome/users/{user_id}/keys")
        .add_request_guard(ProtocolVersionRangeGuard::new(
            protocol::BIOME_KEYS_PROTOCOL_MIN,
            protocol::BIOME_PROTOCOL_VERSION,
        ))
        .add_method(Method::Post, move |request, payload| {
            Box::new(handle_post(
                rest_config.clone(),
                key_store.clone(),
                secret_manager.clone(),
                request,
                payload,
            ))
        })
        .add_method(Method::Get, move |request, _| {
            Box::new(handle_get(
                rest_config.clone(),
                key_store.clone(),
                secret_manager.clone(),
                request,
            ))
        })
        .add_method(Method::Patch, move |request, payload| {
            Box::new(handle_patch(
                rest_config,
                key_store,
                secret_manager,
                request,
                payload,
            ))
        })
}

async fn handle_post(
    rest_config: Arc<BiomeRestConfig>,
    key_store: Arc<dyn KeyStore<Key>>,
    secret_manager: Arc<dyn SecretManager>,
    request: HttpRequest,
    payload: Payload,
) -> Result<HttpResponse, ActixError> {
    let user_id = match request.match_info().get("user_id") {
        Some(id) => id.to_owned(),
        None => {
            error!("User ID is not in path request");
            return Ok(HttpResponse::InternalServerError().json(ErrorResponse::internal_error()));
        }
    };

    match authorize_user(&request, &user_id, &secret_manager, &rest_config) {
        AuthorizationResult::Authorized => (),
        AuthorizationResult::Unauthorized(msg) => {
            return Ok(HttpResponse::Unauthorized().json(ErrorResponse::unauthorized(&msg)));
        }
        AuthorizationResult::Failed => {
            return Ok(HttpResponse::InternalServerError().json(ErrorResponse::internal_error()));
        }
    }
    let bytes = into_bytes(payload).await?;

    let new_key = match serde_json::from_slice::<NewKey>(&bytes) {
        Ok(val) => val,
        Err(err) => {
            debug!("Error parsing payload {}", err);
            return Ok(
                HttpResponse::BadRequest().json(ErrorResponse::bad_request(&format!(
                    "Failed to parse payload: {}",
                    err
                ))),
            );
        }
    };
    let key = Key::new(
        &new_key.public_key,
        &new_key.encrypted_private_key,
        &user_id,
        &new_key.display_name,
    );

    match key_store.add_key(key) {
        Ok(()) => Ok(HttpResponse::Ok().json(json!({ "message": "Key added successfully" }))),
        Err(err) => {
            debug!("Failed to add new key to database {}", err);
            match err {
                KeyStoreError::DuplicateKeyError(msg) => {
                    Ok(HttpResponse::BadRequest().json(ErrorResponse::bad_request(&msg)))
                }
                KeyStoreError::UserDoesNotExistError(msg) => {
                    Ok(HttpResponse::BadRequest().json(ErrorResponse::bad_request(&msg)))
                }
                _ => Ok(HttpResponse::InternalServerError().json(ErrorResponse::internal_error())),
            }
        }
    }
}

async fn handle_get(
    rest_config: Arc<BiomeRestConfig>,
    key_store: Arc<dyn KeyStore<Key>>,
    secret_manager: Arc<dyn SecretManager>,
    request: HttpRequest,
) -> Result<HttpResponse, ActixError> {
    let user_id = match request.match_info().get("user_id") {
        Some(id) => id.to_owned(),
        None => {
            error!("User ID is not in path request");
            return Ok(HttpResponse::InternalServerError().json(ErrorResponse::internal_error()));
        }
    };

    match authorize_user(&request, &user_id, &secret_manager, &rest_config) {
        AuthorizationResult::Authorized => (),
        AuthorizationResult::Unauthorized(msg) => {
            return Ok(HttpResponse::Unauthorized().json(ErrorResponse::unauthorized(&msg)));
        }
        AuthorizationResult::Failed => {
            return Ok(HttpResponse::InternalServerError().json(ErrorResponse::internal_error()));
        }
    }

    match key_store.list_keys(Some(&user_id)) {
        Ok(keys) => Ok(HttpResponse::Ok().json(json!({ "data": keys }))),
        Err(err) => {
            debug!("Failed to fetch keys {}", err);
            Ok(HttpResponse::InternalServerError().json(ErrorResponse::internal_error()))
        }
    }
}

async fn handle_patch(
    rest_config: Arc<BiomeRestConfig>,
    key_store: Arc<dyn KeyStore<Key>>,
    secret_manager: Arc<dyn SecretManager>,
    request: HttpRequest,
    payload: Payload,
) -> Result<HttpResponse, ActixError> {
    let user_id = match request.match_info().get("user_id") {
        Some(id) => id.to_owned(),
        None => {
            error!("User ID is not in path request");
            return Ok(HttpResponse::InternalServerError().json(ErrorResponse::internal_error()));
        }
    };

    match authorize_user(&request, &user_id, &secret_manager, &rest_config) {
        AuthorizationResult::Authorized => (),
        AuthorizationResult::Unauthorized(msg) => {
            return Ok(HttpResponse::Unauthorized().json(ErrorResponse::unauthorized(&msg)));
        }
        AuthorizationResult::Failed => {
            return Ok(HttpResponse::InternalServerError().json(ErrorResponse::internal_error()));
        }
    }

    let bytes = into_bytes(payload).await?;
    let updated_key = match serde_json::from_slice::<UpdatedKey>(&bytes) {
        Ok(val) => val,
        Err(err) => {
            debug!("Error parsing payload {}", err);
            return Ok(
                HttpResponse::BadRequest().json(ErrorResponse::bad_request(&format!(
                    "Failed to parse payload: {}",
                    err
                ))),
            );
        }
    };

    match key_store.update_key(
        &updated_key.public_key,
        &user_id,
        &updated_key.new_display_name,
    ) {
        Ok(()) => Ok(HttpResponse::Ok().json(json!({ "message": "Key updated successfully" }))),
        Err(err) => {
            debug!("Failed to update key {}", err);
            match err {
                KeyStoreError::NotFoundError(msg) => {
                    Ok(HttpResponse::NotFound().json(ErrorResponse::not_found(&msg)))
                }
                _ => Ok(HttpResponse::InternalServerError().json(ErrorResponse::internal_error())),
            }
        }
    }
}

enum AuthorizationResult {
    Authorized,
    Unauthorized(String),
    Failed,
}

fn authorize_user(
    request: &HttpRequest,
    user_id: &str,
    secret_manager: &Arc<dyn SecretManager>,
    rest_config: &BiomeRestConfig,
) -> AuthorizationResult {
    let auth_token = match get_authorization_token(&request) {
        Ok(token) => token,
        Err(err) => {
            debug!("Failed to get token: {}", err);
            return AuthorizationResult::Unauthorized("User is not authorized".to_string());
        }
    };

    let secret = match secret_manager.secret() {
        Ok(secret) => secret,
        Err(err) => {
            debug!("Failed to fetch secret {}", err);
            return AuthorizationResult::Failed;
        }
    };

    if let Err(err) = validate_token(&auth_token, &secret, &rest_config.issuer(), |claim| {
        if user_id != claim.user_id() {
            return Err(TokenValidationError::InvalidClaim(format!(
                "User is not update keys for user {}",
                user_id
            )));
        }
        Ok(())
    }) {
        debug!("Invalid token: {}", err);
        return AuthorizationResult::Unauthorized("User is not authorized".to_string());
    };

    AuthorizationResult::Authorized
}

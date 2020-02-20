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
use uuid::Uuid;

use crate::actix_web::{web::Payload, Error, HttpRequest, HttpResponse};
use crate::protocol;
use crate::rest_api::{into_bytes, ErrorResponse, Method, ProtocolVersionRangeGuard, Resource};

use super::super::rest_api::BiomeRestConfig;
use super::super::sessions::{AccessTokenIssuer, ClaimsBuilder, TokenIssuer};
use super::super::user::store::{diesel::SplinterUserStore, SplinterUser, UserStore};
use super::store::{
    diesel::SplinterCredentialsStore, CredentialsStore, CredentialsStoreError,
    UserCredentialsBuilder,
};

#[derive(Deserialize)]
struct UsernamePassword {
    username: String,
    hashed_password: String,
}

/// Defines a REST endpoint to add a user and credentials to the database
/// The payload should be in the JSON format:
///   {
///       "username": <username of new user>
///       "hashed_password": <hash of the password the user will use to log in>
///   }
pub fn make_register_route(
    credentials_store: Arc<SplinterCredentialsStore>,
    user_store: Arc<SplinterUserStore>,
    rest_config: Arc<BiomeRestConfig>,
) -> Resource {
    Resource::build("/biome/register")
        .add_request_guard(ProtocolVersionRangeGuard::new(
            protocol::BIOME_REGISTER_PROTOCOL_MIN,
            protocol::BIOME_PROTOCOL_VERSION,
        ))
        .add_method(Method::Post, move |_, payload| {
            let credentials_store = credentials_store.clone();
            let user_store = user_store.clone();
            let rest_config = rest_config.clone();

            Box::new(make_register_method(
                credentials_store,
                user_store,
                rest_config,
                payload,
            ))
        })
}

async fn make_register_method(
    credentials_store: Arc<SplinterCredentialsStore>,
    user_store: Arc<SplinterUserStore>,
    rest_config: Arc<BiomeRestConfig>,
    payload: Payload,
) -> Result<HttpResponse, Error> {
    let bytes = into_bytes(payload).await?;
    let username_password = match serde_json::from_slice::<UsernamePassword>(&bytes) {
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
    let user_id = Uuid::new_v4().to_string();
    let splinter_user = SplinterUser::new(&user_id);
    match user_store.add_user(splinter_user) {
        Ok(()) => {
            let credentials_builder: UserCredentialsBuilder = Default::default();
            let credentials = match credentials_builder
                .with_user_id(&user_id)
                .with_username(&username_password.username)
                .with_password(&username_password.hashed_password)
                .with_password_encryption_cost(rest_config.password_encryption_cost())
                .build()
            {
                Ok(credential) => credential,
                Err(err) => {
                    debug!("Failed to create credentials {}", err);
                    return Ok(
                        HttpResponse::InternalServerError().json(ErrorResponse::internal_error())
                    );
                }
            };

            match credentials_store.add_credentials(credentials) {
                Ok(()) => {
                    Ok(HttpResponse::Ok().json(json!({ "message": "User created successfully" })))
                }
                Err(err) => {
                    debug!("Failed to add new credentials to database {}", err);
                    match err {
                        CredentialsStoreError::DuplicateError(err) => {
                            Ok(HttpResponse::BadRequest().json(ErrorResponse::bad_request(
                                &format!("Failed to create user: {}", err),
                            )))
                        }
                        _ => Ok(HttpResponse::InternalServerError()
                            .json(ErrorResponse::internal_error())),
                    }
                }
            }
        }
        Err(err) => {
            debug!("Failed to add new user to database {}", err);
            Ok(HttpResponse::InternalServerError().json(ErrorResponse::internal_error()))
        }
    }
}

/// Defines a REST endpoint for login
pub fn make_login_route(
    credentials_store: Arc<SplinterCredentialsStore>,
    rest_config: Arc<BiomeRestConfig>,
    token_issuer: Arc<AccessTokenIssuer>,
) -> Resource {
    Resource::build("/biome/login")
        .add_request_guard(ProtocolVersionRangeGuard::new(
            protocol::BIOME_LOGIN_PROTOCOL_MIN,
            protocol::BIOME_PROTOCOL_VERSION,
        ))
        .add_method(Method::Post, move |_, payload| {
            let credentials_store = credentials_store.clone();
            let rest_config = rest_config.clone();
            let token_issuer = token_issuer.clone();
            Box::new(add_login_method(
                credentials_store,
                rest_config,
                token_issuer,
                payload,
            ))
        })
}

async fn add_login_method(
    credentials_store: Arc<SplinterCredentialsStore>,
    rest_config: Arc<BiomeRestConfig>,
    token_issuer: Arc<AccessTokenIssuer>,
    payload: Payload,
) -> Result<HttpResponse, Error> {
    let bytes = into_bytes(payload).await?;

    let username_password = match serde_json::from_slice::<UsernamePassword>(&bytes) {
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

    let credentials =
        match credentials_store.fetch_credential_by_username(&username_password.username) {
            Ok(credentials) => credentials,
            Err(err) => {
                debug!("Failed to fetch credentials {}", err);
                match err {
                    CredentialsStoreError::NotFoundError(_) => {
                        return Ok(HttpResponse::BadRequest().json(ErrorResponse::bad_request(
                            &format!("Username not found: {}", username_password.username),
                        )));
                    }
                    _ => {
                        return Ok(HttpResponse::InternalServerError()
                            .json(ErrorResponse::internal_error()))
                    }
                }
            }
        };

    match credentials.verify_password(&username_password.hashed_password) {
        Ok(is_valid) => {
            if is_valid {
                let claim_builder: ClaimsBuilder = Default::default();
                let claim = match claim_builder
                    .with_user_id(&credentials.user_id)
                    .with_issuer(&rest_config.issuer())
                    .with_duration(rest_config.access_token_duration())
                    .build()
                {
                    Ok(claim) => claim,
                    Err(err) => {
                        debug!("Failed to build claim {}", err);
                        return Ok(HttpResponse::InternalServerError()
                            .json(ErrorResponse::internal_error()));
                    }
                };

                let token = match token_issuer.issue_token_with_claims(claim) {
                    Ok(token) => token,
                    Err(err) => {
                        debug!("Failed to issue token {}", err);
                        return Ok(HttpResponse::InternalServerError()
                            .json(ErrorResponse::internal_error()));
                    }
                };
                Ok(
                    HttpResponse::Ok().json(json!({ "message": "Successful login",
                                      "user_id": credentials.user_id ,
                                      "token": token  })),
                )
            } else {
                Ok(HttpResponse::BadRequest().json(ErrorResponse::bad_request("Invalid password")))
            }
        }
        Err(err) => {
            debug!("Failed to verify password {}", err);
            Ok(HttpResponse::InternalServerError().json(ErrorResponse::internal_error()))
        }
    }
}

/// Defines a REST endpoint to list users from the db
pub fn make_list_route(credentials_store: Arc<SplinterCredentialsStore>) -> Resource {
    Resource::build("/biome/users")
        .add_request_guard(ProtocolVersionRangeGuard::new(
            protocol::BIOME_LIST_USERS_PROTOCOL_MIN,
            protocol::BIOME_PROTOCOL_VERSION,
        ))
        .add_method(Method::Get, move |_, _| {
            let credentials_store = credentials_store.clone();
            match credentials_store.get_usernames() {
                Ok(users) => Ok(HttpResponse::Ok().json(users)),
                Err(err) => {
                    debug!("Failed to get users from the database {}", err);
                    Ok(HttpResponse::InternalServerError().json(ErrorResponse::internal_error()))
                }
            }
        })
}

/// Defines REST endpoints to modify, delete, or fetch a specific user
pub fn make_user_routes(
    credentials_store: Arc<SplinterCredentialsStore>,
    user_store: Arc<SplinterUserStore>,
) -> Resource {
    let credentials_store_modify = credentials_store.clone();
    let credentials_store_fetch = credentials_store.clone();
    let credentials_store_delete = credentials_store;
    let user_store_modify = user_store.clone();
    let user_store_delete = user_store;
    Resource::build("/biome/users/{id}")
        .add_request_guard(ProtocolVersionRangeGuard::new(
            protocol::BIOME_USER_PROTOCOL_MIN,
            protocol::BIOME_PROTOCOL_VERSION,
        ))
        .add_method(Method::Put, move |request, payload| {
            Box::new(add_modify_user_method(
                request,
                payload,
                credentials_store_modify.clone(),
                user_store_modify.clone(),
            ))
        })
        .add_method(Method::Get, move |request, _| {
            Box::new(add_fetch_user_method(
                request,
                credentials_store_fetch.clone(),
            ))
        })
        .add_method(Method::Delete, move |request, payload| {
            Box::new(add_delete_user_method(
                request,
                payload,
                credentials_store_delete.clone(),
                user_store_delete.clone(),
            ))
        })
}

/// Defines a REST endpoint to fetch a user from the database
/// returns the user's ID and username
fn add_fetch_user_method(
    request: HttpRequest,
    credentials_store: Arc<SplinterCredentialsStore>,
) -> Result<HttpResponse, Error> {
    let user_id = if let Some(t) = request.match_info().get("id") {
        t.to_string()
    } else {
        return Ok(HttpResponse::BadRequest().json(ErrorResponse::bad_request(
            &"Failed to process request: no user id".to_string(),
        )));
    };
    match credentials_store.fetch_username_by_id(&user_id) {
        Ok(user) => Ok(HttpResponse::Ok().json(user)),
        Err(err) => {
            debug!("Failed to get user from the database {}", err);
            match err {
                CredentialsStoreError::NotFoundError(_) => Ok(HttpResponse::NotFound().json(
                    ErrorResponse::not_found(&format!("User ID not found: {}", &user_id)),
                )),
                _ => Ok(HttpResponse::InternalServerError().json(ErrorResponse::internal_error())),
            }
        }
    }
}

/// Defines a REST endpoint to edit a user's credentials in the database
/// The payload should be in the JSON format:
///   {
///       "username": <existing username of the user>
///       "hashed_password": <hash of the user's existing password>
///       "new_password": OPTIONAL <hash of the user's updated password>
///   }
async fn add_modify_user_method(
    request: HttpRequest,
    payload: Payload,
    credentials_store: Arc<SplinterCredentialsStore>,
    user_store: Arc<SplinterUserStore>,
) -> Result<HttpResponse, Error> {
    let user_id = if let Some(t) = request.match_info().get("id") {
        t.to_string()
    } else {
        return Ok(HttpResponse::BadRequest().json(ErrorResponse::bad_request(
            &"Failed to parse payload: no user id".to_string(),
        )));
    };
    let bytes = into_bytes(payload).await?;

    let body = match serde_json::from_slice::<serde_json::Value>(&bytes) {
        Ok(val) => val,
        Err(err) => {
            debug!("Error parsing request body {}", err);
            return Ok(
                HttpResponse::BadRequest().json(ErrorResponse::bad_request(&format!(
                    "Failed to parse payload body: {}",
                    err
                ))),
            );
        }
    };
    let username_password = match serde_json::from_slice::<UsernamePassword>(&bytes) {
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

    let credentials =
        match credentials_store.fetch_credential_by_username(&username_password.username) {
            Ok(credentials) => credentials,
            Err(err) => {
                debug!("Failed to fetch credentials {}", err);
                match err {
                    CredentialsStoreError::NotFoundError(_) => {
                        return Ok(HttpResponse::NotFound().json(ErrorResponse::not_found(
                            &format!("Username not found: {}", username_password.username),
                        )));
                    }
                    _ => {
                        return Ok(HttpResponse::InternalServerError()
                            .json(ErrorResponse::internal_error()))
                    }
                }
            }
        };
    let splinter_user = SplinterUser::new(&user_id);
    match credentials.verify_password(&username_password.hashed_password) {
        Ok(is_valid) => {
            if is_valid {
                let new_password = match body.get("new_password") {
                    Some(val) => match val.as_str() {
                        Some(val) => val,
                        None => &username_password.hashed_password,
                    },
                    None => &username_password.hashed_password,
                };

                match user_store.update_user(splinter_user) {
                    Ok(()) => {
                        match credentials_store.update_credentials(
                            &user_id,
                            &username_password.username,
                            &new_password,
                        ) {
                            Ok(()) => Ok(HttpResponse::Ok()
                                .json(json!({ "message": "User updated successfully" }))),
                            Err(err) => {
                                debug!("Failed to update credentials in database {}", err);
                                match err {
                                    CredentialsStoreError::DuplicateError(err) => {
                                        Ok(HttpResponse::BadRequest().json(
                                            ErrorResponse::bad_request(&format!(
                                                "Failed to update user: {}",
                                                err
                                            )),
                                        ))
                                    }
                                    _ => Ok(HttpResponse::InternalServerError()
                                        .json(ErrorResponse::internal_error())),
                                }
                            }
                        }
                    }
                    Err(err) => {
                        debug!("Failed to update user in database {}", err);
                        Ok(HttpResponse::InternalServerError()
                            .json(ErrorResponse::internal_error()))
                    }
                }
            } else {
                Ok(HttpResponse::BadRequest().json(ErrorResponse::bad_request("Invalid password")))
            }
        }
        Err(err) => {
            debug!("Failed to verify password {}", err);
            Ok(HttpResponse::InternalServerError().json(ErrorResponse::internal_error()))
        }
    }
}

/// Defines a REST endpoint to delete a user from the database
/// The payload should be in the JSON format:
///   {
///       "username": <existing username of the user>
///       "hashed_password": <hash of the user's existing password>
///   }
async fn add_delete_user_method(
    request: HttpRequest,
    payload: Payload,
    credentials_store: Arc<SplinterCredentialsStore>,
    user_store: Arc<SplinterUserStore>,
) -> Result<HttpResponse, Error> {
    let user_id = if let Some(t) = request.match_info().get("id") {
        t.to_string()
    } else {
        return Ok(HttpResponse::BadRequest().json(ErrorResponse::bad_request(
            &"Failed to parse payload: no user id".to_string(),
        )));
    };
    let bytes = into_bytes(payload).await?;
    let username_password = match serde_json::from_slice::<UsernamePassword>(&bytes) {
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

    let credentials =
        match credentials_store.fetch_credential_by_username(&username_password.username) {
            Ok(credentials) => credentials,
            Err(err) => {
                debug!("Failed to fetch credentials {}", err);
                match err {
                    CredentialsStoreError::NotFoundError(_) => {
                        return Ok(HttpResponse::NotFound().json(ErrorResponse::not_found(
                            &format!("Username not found: {}", username_password.username),
                        )));
                    }
                    _ => {
                        return Ok(HttpResponse::InternalServerError()
                            .json(ErrorResponse::internal_error()))
                    }
                }
            }
        };

    match credentials.verify_password(&username_password.hashed_password) {
        Ok(is_valid) => {
            if is_valid {
                match user_store.remove_user(&user_id) {
                    Ok(()) => {
                        Ok(HttpResponse::Ok()
                            .json(json!({ "message": "User deleted sucessfully" })))
                    }
                    Err(err) => {
                        debug!("Failed to delete user in database {}", err);
                        Ok(HttpResponse::InternalServerError()
                            .json(ErrorResponse::internal_error()))
                    }
                }
            } else {
                Ok(HttpResponse::BadRequest().json(ErrorResponse::bad_request("Invalid password")))
            }
        }
        Err(err) => {
            debug!("Failed to verify password {}", err);
            Ok(HttpResponse::InternalServerError().json(ErrorResponse::internal_error()))
        }
    }
}

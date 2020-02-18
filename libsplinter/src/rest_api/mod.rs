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

//! Rest API Module.
//!
//! Module for creating REST APIs for services.
//!
//! Below is an example of a `struct` that implements `ResouceProvider` and then passes its resources
//! to a running instance of `RestApi`.
//!
//! ```
//! use splinter::rest_api::{Resource, Method, RestApiBuilder, RestResourceProvider};
//! use actix_web::HttpResponse;
//! use futures::IntoFuture;
//!
//! struct IndexResource {
//!     pub name: String
//! }
//!
//! impl RestResourceProvider for IndexResource {
//!     fn resources(&self) -> Vec<Resource> {
//!         let name = self.name.clone();
//!
//!         vec![Resource::build("/index").add_method(Method::Get, move |r, p| {
//!             Box::new(
//!                 HttpResponse::Ok()
//!                 .body(format!("Hello, I am {}", name))
//!                 .into_future())
//!         })]
//!     }
//! }
//!
//! let index_resource = IndexResource { name: "Taco".to_string() };
//!
//! RestApiBuilder::new()
//!     .add_resources(index_resource.resources())
//!     .with_bind("localhost:8080")
//!     .build()
//!     .unwrap()
//!     .run();
//! ```

mod errors;
mod events;
pub mod paging;
mod response_models;

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use actix_web::{
    error::ErrorBadRequest, middleware, web, App, Error as ActixError, HttpRequest, HttpResponse,
    HttpServer,
};
use futures::StreamExt;
use percent_encoding::{AsciiSet, CONTROLS};
use protobuf::{self, Message};
use std::boxed::Box;
use std::sync::{mpsc, Arc};
use std::thread;

pub use errors::{RequestError, ResponseError, RestApiServerError};

pub use events::{new_websocket_event_sender, EventSender};

pub use response_models::ErrorResponse;

const QUERY_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'<')
    .add(b'>')
    .add(b'`')
    .add(b'=')
    .add(b'!')
    .add(b'{')
    .add(b'}')
    .add(b'[')
    .add(b']')
    .add(b':')
    .add(b',');

/// A `RestResourceProvider` provides a list of resources that are consumed by `RestApi`.
pub trait RestResourceProvider {
    fn resources(&self) -> Vec<Resource>;
}

pub type HandlerFunction = Box<
    dyn Fn(HttpRequest, web::Payload) -> Result<HttpResponse, ActixError> + Send + Sync + 'static,
>;

/// Shutdown handle returned by `RestApi::run`. Allows rest api instance to be shut down
/// gracefully.
pub struct RestApiShutdownHandle {
    do_shutdown: Box<dyn Fn() -> Result<(), RestApiServerError> + Send>,
}

impl RestApiShutdownHandle {
    pub fn shutdown(&self) -> Result<(), RestApiServerError> {
        (*self.do_shutdown)()
    }
}

pub struct Request(HttpRequest, web::Payload);

impl From<(HttpRequest, web::Payload)> for Request {
    fn from((http_request, payload): (HttpRequest, web::Payload)) -> Self {
        Self(http_request, payload)
    }
}

impl Into<(HttpRequest, web::Payload)> for Request {
    fn into(self) -> (HttpRequest, web::Payload) {
        (self.0, self.1)
    }
}

pub struct Response(HttpResponse);

impl From<HttpResponse> for Response {
    fn from(res: HttpResponse) -> Self {
        Self(res)
    }
}

impl Future for Response {
    type Output = Result<HttpResponse, ActixError>;

    fn poll(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };
        loop {
            match unsafe { Pin::new_unchecked(&mut this.0) }.poll_next(ctx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(Ok(this.0)),
                Poll::Ready(Some(res)) => return Poll::Ready(Ok(res)),
            };
        }
    }
}

impl std::fmt::Debug for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

/// Rest methods compatible with `RestApi`.
#[derive(Clone)]
pub enum Method {
    Get,
    Post,
    Put,
    Patch,
    Delete,
    Head,
}

/// `Resource` represents a RESTful endpoint.
///
/// ```
/// use splinter::rest_api::{Resource, Method};
/// use actix_web::HttpResponse;
/// use futures::IntoFuture;
///
/// Resource::build("/index")
///     .add_method(Method::Get, |r, p| {
///         Box::new(
///             HttpResponse::Ok()
///                 .body("Hello, World")
///                 .into_future()
///         )
///     });
/// ```
#[derive(Clone)]
pub struct Resource {
    route: String,
    request_guards: Vec<Arc<dyn RequestGuard>>,
    methods: Vec<(Method, Arc<HandlerFunction>)>,
}

impl Resource {
    #[deprecated(note = "Please use the `build` and `add_method` methods instead")]
    pub fn new<F>(method: Method, route: &str, handle: F) -> Self
    where
        F: Fn(HttpRequest, web::Payload) -> Result<HttpResponse, ActixError>
            + Send
            + Sync
            + 'static,
    {
        Self::build(route).add_method(method, handle)
    }

    pub fn build(route: &str) -> Self {
        Self {
            route: route.to_string(),
            methods: vec![],
            request_guards: vec![],
        }
    }

    pub fn add_method<F>(mut self, method: Method, handle: F) -> Self
    where
        F: Fn(HttpRequest, web::Payload) -> Result<HttpResponse, ActixError>
            + Send
            + Sync
            + 'static,
    {
        self.methods.push((method, Arc::new(Box::new(handle))));
        self
    }

    /// Adds a RequestGuard to the given Resource.
    ///
    /// This guard applies to all methods defined for this resource.
    ///
    /// # Example
    ///
    /// ```
    /// use splinter::rest_api::{Resource, Method, Continuation};
    /// use actix_web::{HttpRequest, HttpResponse};
    /// use futures::IntoFuture;
    ///
    /// Resource::build("/index")
    ///     .add_request_guard(|r: &HttpRequest| {
    ///         if !r.headers().contains_key("GuardFlag") {
    ///             Continuation::terminate(
    ///                 HttpResponse::BadRequest().finish().into_future(),
    ///             )
    ///         } else {
    ///             Continuation::Continue
    ///         }
    ///     })
    ///     .add_method(Method::Get, |r, p| {
    ///         Box::new(
    ///             HttpResponse::Ok()
    ///                 .body("Hello, World")
    ///                 .into_future()
    ///         )
    ///     });
    /// ```
    pub fn add_request_guard<RG>(mut self, guard: RG) -> Self
    where
        RG: RequestGuard + Clone + 'static,
    {
        self.request_guards.push(Arc::new(guard));
        self
    }

    fn into_route(self) -> actix_web::Resource {
        let resource = web::resource(&self.route);

        let request_guards = self.request_guards;
        self.methods
            .into_iter()
            .fold(resource, |resource, (method, handler)| {
                let guards = request_guards.clone();
                let func = move |r: HttpRequest, p: web::Payload| {
                    // This clone satisfies a requirement that this be FnOnce
                    if !guards.is_empty() {
                        for guard in guards.clone() {
                            match guard.evaluate(&r) {
                                Continuation::Terminate(result) => return result,
                                Continuation::Continue => (),
                            }
                        }
                    }
                    (handler)(r, p)
                };
                resource.route(match method {
                    Method::Get => web::get().to(func),
                    Method::Post => web::post().to(func),
                    Method::Put => web::put().to(func),
                    Method::Patch => web::patch().to(func),
                    Method::Delete => web::delete().to(func),
                    Method::Head => web::head().to(func),
                })
            })
    }
}

/// A continuation indicates whether or not a guard should allow a given request to continue, or to
/// return a result.
pub enum Continuation {
    Continue,
    Terminate(Result<HttpResponse, ActixError>),
}

impl Continuation {
    /// Wraps the given future in the Continuation::Terminate variant.
    pub fn terminate<F>(fut: F) -> Continuation
    where
        F: Future<Output = Result<HttpResponse, ActixError>> + 'static,
    {
        Continuation::Terminate(Box::new(fut))
    }
}

/// A guard checks the request content in advance, and either continues the request, or
/// returns a terminating result.
pub trait RequestGuard: Send + Sync {
    /// Evaluates the request and determines whether or not the request should be continued or
    /// short-circuited with a terminating future.
    fn evaluate(&self, req: &HttpRequest) -> Continuation;
}

impl<F> RequestGuard for F
where
    F: Fn(&HttpRequest) -> Continuation + Sync + Send,
{
    fn evaluate(&self, req: &HttpRequest) -> Continuation {
        (*self)(req)
    }
}

impl RequestGuard for Box<dyn RequestGuard> {
    fn evaluate(&self, req: &HttpRequest) -> Continuation {
        (**self).evaluate(req)
    }
}

/// Guards requests based on a minimum protocol version.
///
/// A protocol version is specified via the HTTP header `"SplinterProtocolVersion"`.  This header
/// is a positive integer value.
#[derive(Clone)]
pub struct ProtocolVersionRangeGuard {
    min: u32,
    max: u32,
}

impl ProtocolVersionRangeGuard {
    /// Constructs a new protocol version guard with the given minimum.
    pub fn new(min: u32, max: u32) -> Self {
        Self { min, max }
    }
}

impl RequestGuard for ProtocolVersionRangeGuard {
    fn evaluate(&self, req: &HttpRequest) -> Continuation {
        if let Some(header_value) = req.headers().get("SplinterProtocolVersion") {
            let parsed_header = header_value
                .to_str()
                .map_err(|err| {
                    format!(
                        "Invalid characters in SplinterProtocolVersion header: {}",
                        err
                    )
                })
                .and_then(|val_str| {
                    val_str.parse::<u32>().map_err(|_| {
                        "SplinterProtocolVersion must be a valid positive integer".to_string()
                    })
                });
            match parsed_header {
                Err(msg) => Continuation::terminate(HttpResponse::BadRequest().json(json!({
                    "message": msg,
                }))),
                Ok(version) if version < self.min => {
                    Continuation::terminate(HttpResponse::BadRequest().json(json!({
                        "message": format!(
                            "Client must support protocol version {} or greater.",
                            self.min,
                        ),
                        "requested_protocol": version,
                        "splinter_protocol": self.max,
                        "libsplinter_version": format!(
                            "{}.{}.{}",
                            env!("CARGO_PKG_VERSION_MAJOR"),
                            env!("CARGO_PKG_VERSION_MINOR"),
                            env!("CARGO_PKG_VERSION_PATCH")
                        )
                    })))
                }
                Ok(version) if version > self.max => {
                    Continuation::terminate(HttpResponse::BadRequest().json(json!({
                        "message": format!(
                            "Client requires a newer protocol than can be provided: {} > {}",
                            version,
                            self.max,
                        ),
                        "requested_protocol": version,
                        "splinter_protocol": self.max,
                        "libsplinter_version": format!(
                            "{}.{}.{}",
                            env!("CARGO_PKG_VERSION_MAJOR"),
                            env!("CARGO_PKG_VERSION_MINOR"),
                            env!("CARGO_PKG_VERSION_PATCH")
                        )
                    })))
                }
                Ok(_) => Continuation::Continue,
            }
        } else {
            // Ignore the missing header, and assume the client will handle version mismatches by
            // inspecting the output
            Continuation::Continue
        }
    }
}

/// `RestApi` is used to create an instance of a restful web server.
#[derive(Clone)]
pub struct RestApi {
    resources: Vec<Resource>,
    bind: String,
}

impl RestApi {
    pub fn run(
        self,
    ) -> Result<(RestApiShutdownHandle, thread::JoinHandle<()>), RestApiServerError> {
        let bind_url = self.bind.to_owned();
        let (tx, rx) = mpsc::channel();

        let join_handle = thread::Builder::new()
            .name("SplinterDRestApi".into())
            .spawn(move || {
                let sys = actix::System::new("SplinterD-Rest-API");
                let mut server = HttpServer::new(move || {
                    let mut app = App::new().wrap(middleware::Logger::default());

                    for resource in self.resources.clone() {
                        app = app.service(resource.into_route());
                    }
                    app
                });

                server = match server.bind(&bind_url) {
                    Ok(server) => server,
                    Err(err) => {
                        error!("Invalid REST API bind {}: {}", bind_url, err);
                        return;
                    }
                };

                let addr = server.disable_signals().system_exit().run();

                if let Err(err) = tx.send(addr) {
                    error!("Unable to send Server Addr: {}", err);
                }

                if let Err(err) = sys.run() {
                    error!("REST Api unexpectedly exiting: {}", err);
                };

                info!("Rest API terminating");
            })?;

        let addr = rx.recv().map_err(|err| {
            RestApiServerError::StartUpError(format!("Unable to receive Server Addr: {}", err))
        })?;

        let do_shutdown = Box::new(move || {
            debug!("Shutting down Rest API");
            if let Err(err) = addr.stop(true).wait() {
                error!("An error occured while shutting down rest API: {:?}", err);
            }
            debug!("Graceful signal sent to Rest API");

            Ok(())
        });

        Ok((RestApiShutdownHandle { do_shutdown }, join_handle))
    }
}

/// Builder `struct` for `RestApi`.
pub struct RestApiBuilder {
    resources: Vec<Resource>,
    bind: Option<String>,
}

impl Default for RestApiBuilder {
    fn default() -> Self {
        Self {
            resources: Vec::new(),
            bind: None,
        }
    }
}

impl RestApiBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_bind(mut self, value: &str) -> Self {
        self.bind = Some(value.to_string());
        self
    }

    pub fn add_resource(mut self, value: Resource) -> Self {
        self.resources.push(value);
        self
    }

    pub fn add_resources(mut self, mut values: Vec<Resource>) -> Self {
        self.resources.append(&mut values);
        self
    }

    pub fn build(self) -> Result<RestApi, RestApiServerError> {
        let bind = self
            .bind
            .ok_or_else(|| RestApiServerError::MissingField("bind".to_string()))?;

        Ok(RestApi {
            bind,
            resources: self.resources,
        })
    }
}

pub async fn into_protobuf<M: Message>(payload: web::Payload) -> Result<M, ActixError> {
    let mut bytes = web::BytesMut::new();
    while let Some(body) = payload.next().await {
        bytes.extend_from_slice(&body?);
    }
    match protobuf::parse_from_bytes::<M>(&bytes) {
        Ok(proto) => Ok(proto),
        Err(err) => Err(ErrorBadRequest(json!({ "message": format!("{}", err) }))),
    }
}

pub async fn into_bytes(payload: web::Payload) -> Result<Vec<u8>, ActixError> {
    let mut bytes = web::BytesMut::new();
    while let Some(body) = payload.next().await {
        bytes.extend_from_slice(&body?);
    }
    Ok(bytes.to_vec())
}

pub fn percent_encode_filter_query(input: &str) -> String {
    percent_encoding::utf8_percent_encode(input, QUERY_ENCODE_SET).to_string()
}

pub fn require_header(header_key: &str, request: &HttpRequest) -> Result<String, RequestError> {
    let header = request.headers().get(header_key).ok_or_else(|| {
        RequestError::MissingHeader(format!("Header {} not included in Request", header_key))
    })?;
    Ok(header
        .to_str()
        .map_err(|err| RequestError::InvalidHeaderValue(format!("Invalid header value: {}", err)))?
        .to_string())
}

pub fn get_authorization_token(request: &HttpRequest) -> Result<String, RequestError> {
    let auth_header = require_header("Authorization", &request)?;
    Ok(auth_header
        .split_whitespace()
        .last()
        .ok_or_else(|| {
            RequestError::InvalidHeaderValue(
                "Authorization token not included in request".to_string(),
            )
        })?
        .to_string())
}

#[cfg(test)]
mod test {
    use super::*;
    use actix_http::Response;
    use futures::IntoFuture;

    #[test]
    fn test_resource() {
        Resource::build("/test")
            .add_method(Method::Get, |_: HttpRequest, _: web::Payload| {
                Box::new(Response::Ok().finish())
            })
            .into_route();
    }

    #[test]
    fn test_resource_with_guard() {
        Resource::build("/test-guarded")
            .add_request_guard(|_: &HttpRequest| {
                Continuation::terminate(Response::BadRequest().finish())
            })
            .add_method(Method::Get, |_: HttpRequest, _: web::Payload| {
                Box::new(Response::Ok().finish())
            })
            .into_route();
    }
}

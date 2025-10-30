use actix_cors::Cors;
use actix_files::NamedFile;
use actix_multipart::form::{MultipartForm, tempfile::TempFile};
use actix_web::{
    App, HttpResponse, HttpServer, get,
    middleware::Logger,
    post,
    web::{self, Data, Redirect},
};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use auth::types::{AuthMiddleware, OIDCData};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::{collections::HashMap, env, sync::Mutex};
use utoipa::{IntoParams, OpenApi};
use utoipa_actix_web::AppExt;
use utoipa_actix_web::service_config::ServiceConfig;
use utoipa_redoc::{Redoc, Servable};

use crate::{
    auth::check_token,
    error::Error,
    s3::{Client, PathType, get_bytes},
};

mod auth;
mod error;
mod s3;

/// Used when quering for the picture of a specific user
#[derive(Debug, Deserialize, IntoParams)]
struct GetQuery {
    /// If the picture should have full quality or a smaller one
    quality: Option<bool>,
}

#[derive(OpenApi)]
struct ApiDoc;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    let client = web::Data::new(Client::new().await);
    let (oidc, auth_url) = OIDCData::get_oidc().await;
    let oidc = web::Data::new(oidc);
    let token_cache: Data<Mutex<HashMap<String, DateTime<Utc>>>> =
        web::Data::new(Mutex::new(HashMap::new()));

    HttpServer::new(move || {
        let cors = Cors::permissive();
        App::new()
            .into_utoipa_app()
            .openapi(ApiDoc::openapi())
            .map(|app| {
                app.wrap(Logger::default())
                    .wrap(cors)
                    .app_data(client.clone())
                    .app_data(oidc.clone())
                    .app_data(token_cache.clone())
            })
            .service(utoipa_actix_web::scope("/auth").configure(auth::config()))
            .service(utoipa_actix_web::scope("/api").configure(config_api()))
            .service(
                utoipa_actix_web::scope("/me")
                    .service(me)
                    .service(upload_interactive)
                    .map(|app| app.wrap(AuthMiddleware::new(auth_url.clone()))),
            )
            .openapi_service(|api| Redoc::with_url("/docs/api", api))
            .service(utoipa_actix_web::scope("").map(|app| {
                app.service(index)
                    .wrap(AuthMiddleware::new(auth_url.clone()))
            }))
            .into_app()
    })
    .bind((
        "0.0.0.0",
        env::var("PORT")
            .expect("port env variable")
            .parse::<u16>()
            .expect("port to number"),
    ))?
    .run()
    .await
}

/// Set up routes for the api part of rfinger (https://rfinger.datasektionen.se/api)
fn config_api() -> impl FnOnce(&mut ServiceConfig) {
    |cfg: &mut ServiceConfig| {
        cfg.service(get_batch).service(get).service(upload).service(nollan);
    }
}

/// MultipartForm form for uploading a profile picture
#[derive(Debug, MultipartForm)]
struct UploadForm {
    /// The image
    image: TempFile,
}

#[get("/")]
async fn index() -> actix_web::Result<NamedFile> {
    Ok(NamedFile::open("index.html")?)
}

/// Upload a picture using the interactive website
#[utoipa::path(tag = "interactive")]
#[post("/")]
async fn upload_interactive(
    s3: web::Data<Client>,
    kthid: web::ReqData<String>,
    MultipartForm(form): MultipartForm<UploadForm>,
) -> Result<Redirect, Error> {
    s3.put_image(
        PathType::Personal(kthid.to_string()),
        kthid.as_ref(),
        get_bytes(&form.image)?,
        &form
            .image
            .content_type
            .ok_or(Error::BadRequest)?
            .to_string(),
    )
    .await?;

    Ok(Redirect::to("/").see_other())
}

/// Get a picture of the currently logged in user
#[utoipa::path(tag = "interactive", params(GetQuery))]
#[get("/")]
async fn me(
    s3: web::Data<Client>,
    id: web::ReqData<String>,
    query: web::Query<GetQuery>,
) -> HttpResponse {
    let response = s3
        .get_image(&id.to_string(), query.quality.unwrap_or(false))
        .await;

    if let Ok((bytes, mime_type)) = response {
        HttpResponse::Ok().content_type(mime_type).body(bytes)
    } else {
        HttpResponse::InternalServerError().finish()
    }
}

/// Get a presigned url to picture of a user using the api
#[utoipa::path(tag = "api", params(GetQuery))]
#[get("/{kthid}")]
async fn get(
    s3: web::Data<Client>,
    kthid: web::Path<String>,
    query: web::Query<GetQuery>,
    cache: web::Data<Mutex<HashMap<String, DateTime<Utc>>>>,
    auth: BearerAuth,
) -> Result<HttpResponse, Error> {
    if !check_token(auth.token(), "get", &cache).await? {
        return Err(Error::Unauthorized);
    }

    Ok(HttpResponse::Ok().body(
        s3.get_presigned_image(&kthid.to_string(), query.quality.unwrap_or(false))
            .await?,
    ))
}

/// Get presigned urls for every user in a list
#[utoipa::path(tag = "api", params(GetQuery), request_body = Vec<String>)]
#[post("/batch")]
async fn get_batch(
    s3: web::Data<Client>,
    body: String,
    query: web::Query<GetQuery>,
    cache: web::Data<Mutex<HashMap<String, DateTime<Utc>>>>,
    auth: BearerAuth,
) -> Result<HttpResponse, Error> {
    if !check_token(auth.token(), "get", &cache).await? {
        return Err(Error::Unauthorized);
    }

    let kthids: Vec<String> = serde_json::from_str(&body)?;

    let mut response: HashMap<String, String> = HashMap::new();

    for kthid in kthids {
        response.insert(
            kthid.clone(),
            s3.get_presigned_image(&kthid.to_string(), query.quality.unwrap_or(false))
                .await?,
        );
    }

    Ok(HttpResponse::Ok().json(response))
}

/// Upload a picture using the api
#[utoipa::path(tag = "api")]
#[post("/{kthid}")]
async fn upload(
    s3: web::Data<Client>,
    kthid: web::Path<String>,
    cache: web::Data<Mutex<HashMap<String, DateTime<Utc>>>>,
    auth: BearerAuth,
    MultipartForm(form): MultipartForm<UploadForm>,
) -> Result<HttpResponse, Error> {
    if !check_token(auth.token(), "upload", &cache).await? {
        return Err(Error::Unauthorized);
    }

    s3.put_image(
        PathType::Personal(kthid.to_string()),
        kthid.as_ref(),
        get_bytes(&form.image)?,
        &form
            .image
            .content_type
            .ok_or(Error::BadRequest)?
            .to_string(),
    )
    .await?;

    Ok(HttpResponse::Ok().finish())
}

/// Upload the initial n0lle picture using the api
#[utoipa::path(tag = "api")]
#[post("/nollan/{kthid}")]
async fn nollan(
    s3: web::Data<Client>,
    kthid: web::Path<String>,
    cache: web::Data<Mutex<HashMap<String, DateTime<Utc>>>>,
    auth: BearerAuth,
    MultipartForm(form): MultipartForm<UploadForm>,
) -> Result<HttpResponse, Error> {
    if !check_token(auth.token(), "nollan", &cache).await? {
        return Err(Error::Unauthorized);
    }

    s3.put_image(
        PathType::Original(kthid.to_string()),
        kthid.as_ref(),
        get_bytes(&form.image)?,
        &form
            .image
            .content_type
            .ok_or(Error::BadRequest)?
            .to_string(),
    )
    .await?;

    Ok(HttpResponse::Ok().finish())
}

use actix_cors::Cors;
use actix_files::NamedFile;
use actix_multipart::form::{MultipartForm, json::Json as MpJson, tempfile::TempFile};
use actix_web::{App, get, middleware::Logger, web};
use actix_web::{HttpResponse, HttpServer, post};
use aws_config::{BehaviorVersion, Region};
use aws_sdk_s3::Client;
use aws_sdk_s3::primitives::ByteStream;
use serde::Deserialize;
use std::io::Read;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    let config = aws_config::load_defaults(BehaviorVersion::latest())
        .await
        .into_builder()
        .endpoint_url("http://localhost:9090")
        .region(Region::new("us-west-2"))
        .build();

    let config = aws_sdk_s3::config::Builder::from(&config)
        .force_path_style(true)
        .build();
    let client = web::Data::new(aws_sdk_s3::Client::from_conf(config));

    HttpServer::new(move || {
        let cors = Cors::permissive();
        App::new()
            .wrap(cors)
            .wrap(Logger::default())
            .app_data(client.clone())
            .service(index)
            .service(change_image)
            .service(get_image)
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}

#[derive(Debug, MultipartForm)]
struct UploadForm {
    image: TempFile,
}

#[get("/")]
async fn index() -> actix_web::Result<NamedFile> {
    Ok(NamedFile::open("index.html")?)
}

#[post("/")]
async fn change_image(
    s3: web::Data<Client>,
    MultipartForm(form): MultipartForm<UploadForm>,
) -> HttpResponse {
    log::debug!("{:?}", form.image.file_name);
    log::debug!("{:?}", form.image.content_type);
    let image_bytes: Vec<u8> = form
        .image
        .file
        .as_file()
        .bytes()
        .map(|x| x.unwrap())
        .collect();

    s3.put_object()
        .bucket("rfinger")
        .key("viktoe")
        .body(ByteStream::from(image_bytes))
        .content_type("image/png")
        .send()
        .await
        .unwrap();

    HttpResponse::Ok().finish()
}

#[get("/{file}")]
async fn get_image(s3: web::Data<Client>, path: web::Path<String>) -> HttpResponse {
    let response = s3
        .get_object()
        .bucket("rfinger")
        .key("viktoe")
        .send()
        .await
        .unwrap();
    let data = response.body.collect().await.unwrap();
    let mime_type = response.content_type.unwrap();
    let bytes = data.into_bytes();

    HttpResponse::Ok().content_type(mime_type).body(bytes)
}

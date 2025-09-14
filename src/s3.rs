use std::{env, fmt::Display, io::{Cursor, Read}};

use actix_multipart::form::tempfile::TempFile;
use actix_web::web::Bytes;
use aws_config::{BehaviorVersion, Region};
use aws_sdk_s3::{error::SdkError, operation::{get_object::{GetObjectError, GetObjectOutput}, put_object::{PutObjectError, PutObjectOutput}}, primitives::ByteStream};
use aws_smithy_runtime_api::http::Response;
use image::{imageops::FilterType, ImageFormat, ImageReader};
use webp::{Encoder, WebPMemory};

use crate::error::Error;

/// Paths to images in s3 bucket
///
/// Original: original_images/<k>/<t>/<kthid>
///     used for the nolle picture
///
/// Personal: personal_images/<k>/<t>/<kthid>
///     used for image uploaded by the person
///
/// Compressed: compressed_images/<k>/<t>/<kthid>
///     used for profile sized picture
///
/// Missing: missing.svg
///     used if no other picture is found
pub enum PathType {
    Compressed(String),
    Personal(String),
    Original(String),
    Missing,
}

impl Display for PathType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PathType::Compressed(kthid) => {
                let mut chars = kthid.chars();
                let first = chars.next().expect("kthid to contain at least 1 letter");
                let second = chars.next().expect("kthid to contain at least 2 letters");
                write!(f, "compressed_images/{first}/{second}/{kthid}")
            }
            PathType::Personal(kthid) => {
                let mut chars = kthid.chars();
                let first = chars.next().expect("kthid to contain at least 1 letter");
                let second = chars.next().expect("kthid to contain at least 2 letters");
                write!(f, "personal_images/{first}/{second}/{kthid}")
            }
            PathType::Original(kthid) => {
                let mut chars = kthid.chars();
                let first = chars.next().expect("kthid to contain at least 1 letter");
                let second = chars.next().expect("kthid to contain at least 2 letters");
                write!(f, "original_images/{first}/{second}/{kthid}")
            }
            PathType::Missing => write!(f, "missing.svg"),
        }
    }
}


/// A s3 bucket client with custom functions
pub struct Client {
    s3_client: aws_sdk_s3::Client,
}

impl Client {
    pub async fn new() -> Self {
        // aws_config needs to be modified to allow local development
        let config = aws_config::load_defaults(BehaviorVersion::latest())
            .await
            .into_builder()
            // .endpoint_url("http://localhost:9090")
            .region(Region::new("eu-west-1"))
            .build();

        // local s3 bucket emplators often only support path style queries
        let config = aws_sdk_s3::config::Builder::from(&config)
            // .force_path_style(true)
            .build();
        let client = aws_sdk_s3::Client::from_conf(config);

        Client { s3_client: client }
    }

    /// Get a picture from s3
    ///
    /// Priority: compressed > personal > original > missing
    ///
    /// if high quality was requested ignore compressed
    pub async fn get_image(&self, kthid: &str, quality: bool) -> Result<(Bytes, String), Error> {
        let mut key;

        // If profile picture requested try to get compressed
        if !quality {
            key = PathType::Compressed(kthid.to_string());

            if let Ok(image) = self.get_object(&key.to_string()).await {
                let image_bytes = image.body.collect().await?.into_bytes();
                let mime_type = image
                    .content_type
                    .clone()
                    .ok_or(Error::InternalServerError(String::from(
                        "image has no mime type",
                    )))?;
                return Ok((image_bytes, mime_type));
            }
        }

        key = PathType::Personal(kthid.to_string());

        // If compressed not found or high quality requested check if a uploaded picture exists
        if let Ok(image) = self.get_object(&key.to_string()).await {
            let image_bytes = image.body.collect().await?.into_bytes();
            let mime_type = image
                .content_type
                .clone()
                .ok_or(Error::InternalServerError(String::from(
                    "image has no mime type",
                )))?;

            // If profile sized picture was requested but not found, create it
            if !quality {
                let compressed = process_image(image_bytes.to_vec(), &mime_type)?;
                self.put_object(
                    PathType::Compressed(kthid.to_string()),
                    compressed.clone(),
                    "image/webp",
                )
                .await?;

                return Ok((Bytes::from(compressed), String::from("image/webp")));
            } else {
                return Ok((image_bytes, mime_type));
            }
        }

        key = PathType::Original(kthid.to_string());

        // If uploaded picture wasnt found try to get nolle picture
        if let Ok(image) = self.get_object(&key.to_string()).await {
            let image_bytes = image.body.collect().await?.into_bytes();
            let mime_type = image
                .content_type
                .clone()
                .ok_or(Error::InternalServerError(String::from(
                    "image has no mime type",
                )))?;

            // If profile sized picture was requested but not found, create it
            if !quality {
                let compressed = process_image(image_bytes.to_vec(), &mime_type)?;
                self.put_object(
                    PathType::Compressed(kthid.to_string()),
                    compressed.clone(),
                    "image/webp",
                )
                .await?;

                return Ok((Bytes::from(compressed), mime_type));
            } else {
                return Ok((image_bytes, mime_type));
            }
        }

        key = PathType::Missing;

        // If no picture was found, return default
        let image = self.get_object(&key.to_string()).await?;
        let image_bytes = image.body.collect().await?.into_bytes();
        let mime_type = image
            .content_type
            .clone()
            .ok_or(Error::InternalServerError(String::from(
                "image has no mime type",
            )))?;
        Ok((image_bytes, mime_type))
    }

    /// Helper function to make getting things from s3 easier
    async fn get_object(
        &self,
        key: &str,
    ) -> Result<GetObjectOutput, SdkError<GetObjectError, Response>> {
        self.s3_client
            .get_object()
            .bucket(env::var("S3_BUCKET").expect("bucket name env"))
            .key(key.to_string())
            .send()
            .await
    }

    /// Upload an image to s3
    ///
    /// Upload it to the specified place and upload a compressed version
    pub async fn put_image(
        &self,
        path: PathType,
        kthid: &str,
        image_bytes: Vec<u8>,
        mime_type: &str,
    ) -> Result<PutObjectOutput, Error> {
        self.put_object(path, image_bytes.clone(), &mime_type)
            .await?;

        let image_bytes = process_image(image_bytes, mime_type)?;

        Ok(self
            .put_object(
                PathType::Compressed(kthid.to_string()),
                image_bytes,
                "image/webp",
            )
            .await?)
    }

    /// Helper function to make putting things in s3 easier
    async fn put_object(
        &self,
        path: PathType,
        image_bytes: Vec<u8>,
        content_type: &str,
    ) -> Result<PutObjectOutput, SdkError<PutObjectError, Response>> {
        self.s3_client
            .put_object()
            .bucket(env::var("S3_BUCKET").expect("bucket name env"))
            .key(path.to_string())
            .body(ByteStream::from(image_bytes))
            .content_type(content_type)
            .send()
            .await
    }
}

/// Extract the image bytes from a temp file
pub fn get_bytes(image: &TempFile) -> Result<Vec<u8>, std::io::Error> {
    image
        .file
        .as_file()
        .bytes()
        .map(|x| x)
        .collect::<Result<Vec<u8>, std::io::Error>>()
}

/// Convert any image to a 480x480 webp encoded image
fn process_image(image_bytes: Vec<u8>, mime_type: &str) -> Result<Vec<u8>, Error> {
    let img_format = ImageFormat::from_mime_type(mime_type).ok_or(Error::InternalServerError(
        String::from("incorrect mime type: {mime_type}"),
    ))?;

    let image = ImageReader::with_format(Cursor::new(image_bytes), img_format).decode()?;

    let image = image.resize(480, 480, FilterType::Lanczos3);

    // Make webp::Encoder from DynamicImage.
    let encoder: Encoder = Encoder::from_image(&image)?;

    // Encode image into WebPMemory.
    let encoded_webp: WebPMemory = encoder.encode(65f32);

    Ok(encoded_webp
        .bytes()
        .map(|x| x)
        .collect::<Result<Vec<u8>, std::io::Error>>()?)
}

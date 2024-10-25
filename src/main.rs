use std::env;
use color_eyre;
use axum::{
    extract::{State, Multipart, Path}, http::{HeaderMap, StatusCode, header}, routing::{get, post}, Json, Router, response::IntoResponse
};
use dotenvy_macro::dotenv;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use tokio::{fs::File, io::AsyncWriteExt, io::AsyncReadExt};
// use tokio::io::AsyncReadExt;
// use serde_json;
use argon2::{
    password_hash::{
        rand_core::OsRng,
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString
    },
    Argon2
};
use jsonwebtoken::{self, decode, encode, DecodingKey, EncodingKey, Header, Validation};
use tower_http::trace::{self, TraceLayer};
use tower::ServiceBuilder;
use tracing::Level;
use uuid::Uuid;

mod middleware;

#[derive(Deserialize, Serialize, Clone, Debug, sqlx::FromRow)]
struct User {
    // id: i32,
    username: String,
    password: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Claims {
    id: i32,
    username: String,
    exp: usize,
}

// #[derive(serde::Serialize)]
// struct JsonError {
//     error: String,
// }

#[axum::debug_handler]
async fn health_check(_req: axum::http::Request<axum::body::Body>,) -> Result<(StatusCode, String), (StatusCode, String)> {
    Ok((StatusCode::OK, "Success!".to_string()))
}

async fn register_user(State(pool): State<PgPool>, Json(user): Json<User>) -> Result<(StatusCode, String), (StatusCode, String)> {
    if user.username == "" && user.password == "" {
        return Err((StatusCode::BAD_REQUEST, "Username or Password empty".to_string()));
    }

    let secert: String = env::var("SECRET").map_err(|_e| ((StatusCode::INTERNAL_SERVER_ERROR, "failed to get secert from env".to_string())))?;

    let password = user.password.as_bytes();
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(password, &salt).map_err(|e| ((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())))?.to_string();

    let result = sqlx::query!(
        "INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id",
        user.username,
        password_hash
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e.to_string())))
    .map(|record| record.id);

    let inserted_id = match result {
        Ok(record) => record,
        Err(e) => return Err(e)
    };

    tracing::info!("New user id is: {inserted_id}");

    let message = format!("User: {} registered!", user.username.clone());
    tracing::info!("{message}");

    let claims = Claims {
        id: inserted_id,
        username: user.username,
        exp: (chrono::Utc::now() + chrono::Duration::hours(24)).timestamp() as usize
    };

    let token = match encode(&Header::default(), &claims, &EncodingKey::from_secret(secert.as_ref())) {
        Ok(tok) => tok,
        Err(e) => {
            tracing::error!("Error generating token {}", e);
            return Err((StatusCode::INTERNAL_SERVER_ERROR, "Error generating token".to_string()));
        }
    };

    return Ok((StatusCode::OK, token));
}

async fn login_user(State(pool): State<PgPool>, Json(credentials): Json<User>) -> Result<(StatusCode, String), (StatusCode, String)> {
    let user = sqlx::query!(
        "SELECT id, password FROM users WHERE username = $1",
        credentials.username
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
    })?;

    let secert: String = env::var("SECRET").map_err(|_e| ((StatusCode::INTERNAL_SERVER_ERROR, "failed to get secert from env".to_string())))?;

    let user = user.ok_or((StatusCode::UNAUTHORIZED, "Invalid credentials".to_string()))?;
    let password = user.password.unwrap();
    let id = user.id;

    let argon2 = Argon2::default();
    let parsed_hash = PasswordHash::new(&password)
    .map_err(|e| ((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())))?;

    if argon2.verify_password(credentials.password.as_bytes(), &parsed_hash).is_ok() {
        let claims = Claims {
            id: id,
            username: credentials.username.clone(),
            exp: (chrono::Utc::now() + chrono::Duration::hours(24)).timestamp() as usize
        };

        let token = match encode(&Header::default(), &claims, &EncodingKey::from_secret(secert.as_ref())) {
            Ok(tok) => tok,
            Err(e) => {
                tracing::error!("Error generating token {}", e);
                return Err((StatusCode::INTERNAL_SERVER_ERROR, "Error generating token".to_string()));
            }
        };
    
        let message = format!("User {} logged in.", credentials.username);
        tracing::info!("{message}");
        return Ok((StatusCode::OK, token));
    }

    Err((StatusCode::INTERNAL_SERVER_ERROR, "Error loging in".to_string()))
}

async fn upload_file(State(pool): State<PgPool>, mut multipart: Multipart) -> Result<(StatusCode, String), (StatusCode, String)> {
    // Process file upload
    if let Some(field) = multipart.next_field().await.map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            // "Failed to process file upload".to_string(),
            format!("Failed to process file upload: {}", e).to_string(),
        )
    })? {
        let file_name = field.file_name()
            .ok_or((StatusCode::BAD_REQUEST, "No filename provided".to_string()))?
            .to_string();
        
        let content_type = field.content_type()
            .ok_or((StatusCode::BAD_REQUEST, "No content type provided".to_string()))?
            .to_string();
        
        // Generate unique filename
        let file_id = Uuid::new_v4();
        let extension = std::path::Path::new(&file_name)
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("bin"); // if no extension then default to .bin
        let new_filename = format!("{}.{}", file_id, extension);
        let upload_path = format!("uploads/{}", new_filename);

        // Ensure uploads directory exists
        tokio::fs::create_dir_all("uploads").await.map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to create upload directory".to_string(),
            )
        })?;

        // Save file
        let contents = field.bytes().await.map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to read file contents".to_string(),
            )
        })?;

        let mut file = File::create(&upload_path).await.map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to create file".to_string(),
            )
        })?;

        file.write_all(&contents).await.map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to write file".to_string(),
            )
        })?;

        // Save file metadata to database
        // sqlx::query!(
        //     // "INSERT INTO files (id, name, content_type, path) VALUES ($1, $2, $3, $4)",
        //     "INSERT INTO files (id, name, content_type) VALUES ($1, $2, $3)",
        //     file_id,
        //     file_name,
        //     content_type,
        //     // upload_path
        // )
        sqlx::query!(
            // "INSERT INTO files (id, name, content_type, path) VALUES ($1, $2, $3, $4)",
            "INSERT INTO files (name, content_type, md5) VALUES ($1, $2, $3)",
            // file_id,
            new_filename,
            // file_name,
            content_type,
            "test",
            // upload_path
        )
        .execute(&pool)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to save file metadata".to_string(),
            )
        })?;

        // Ok(Json(UploadResponse {
        //     file_url: format!("/files/{}", file_id),
        // }));
        return Ok((StatusCode::OK, format!("/files/{}", file_id)))

        // tracing::info!("{} uploaded {} files")
    } else {
        return Err((StatusCode::BAD_REQUEST, "{ 'error': 'No file provided' }".to_string()))
    };
}

async fn get_file_by_id(
    State(pool): State<PgPool>,
    // Path(file_id): Path<Uuid>,
    Path(file_id): Path<i32>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    // 1. Get file metadata from database using ID
    let file_meta = sqlx::query!(
        // "SELECT name, content_type, path FROM files WHERE id = $1",
        "SELECT name, content_type FROM files WHERE id = $1",
        file_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Database error".to_string()))?
    .ok_or((StatusCode::NOT_FOUND, "File not found".to_string()))?;

    // 2. Read file contents
    let uploaded_file_path = format!("/upload/{}", &file_meta.name.clone().unwrap());
    let mut file = File::open(&uploaded_file_path)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, "File not found".to_string()))?;

    let mut contents = Vec::new();
    file.read_to_end(&mut contents)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Failed to read file".to_string()))?;

    // 3. Return file with proper headers
    Ok((
        [
            (header::CONTENT_TYPE, file_meta.content_type),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{}\"", file_meta.name.unwrap()),
            ),
        ],
        contents,
    ))
}

// #[dotenvy::load]
#[tokio::main]
async fn main() -> Result<(), color_eyre::Report> {
    color_eyre::install()?;
    dotenvy::dotenv()?;
    // dotenv!();

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&env::var("DATABASE_URL")?).await?;

    tracing::info!("Connected to database");

    tracing_subscriber::fmt()
        .with_target(false)
        .compact()
        .init();

    let auth_routes = Router::new()
        .route("/upload", post(upload_file))
        .route("/file/:file_id", get(get_file_by_id))
        .layer(ServiceBuilder::new().layer(axum::middleware::from_fn(middleware::authorization_middleware)));

    let app = Router::new()
        .route("/", get(health_check))
        .route("/register", post(register_user))
        .route("/login", post(login_user))
        .nest("", auth_routes)
        // .route("/upload", post(upload_file))
        .with_state(pool)
        .layer(
            ServiceBuilder::new()
            .layer(
                TraceLayer::new_for_http()
                .make_span_with(trace::DefaultMakeSpan::new()
                .level(Level::INFO))
                .on_response(trace::DefaultOnResponse::new()
                .level(Level::INFO))
            )

        );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await.unwrap();
    axum::serve(listener, app.into_make_service()).await.unwrap();

    // log::info!("Write Uploaded files to tempdir and if upload fails drop tempdir to delete files and try again");
    // log::info!("Or maybe just write file to upload dir and of chunk not whole then delete last chunk");
    // log::info!("Frontend loadingbar chunk number as progress");

    Ok(())
}

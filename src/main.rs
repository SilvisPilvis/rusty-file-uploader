use color_eyre;
use axum::{
    extract::{State, Multipart, Path}, http::{HeaderMap, StatusCode, header}, routing::{get, post}, Json, Router, response::IntoResponse
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use tokio::{fs::File, io::AsyncWriteExt};
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

#[derive(Serialize, Deserialize)]
struct Claims {
    id: i32,
    username: String,
    exp: usize,
}

#[derive(Serialize)]
struct UploadResponse {
    file_url: String,
}

#[axum::debug_handler]
async fn health_check(_req: axum::http::Request<axum::body::Body>,) -> Result<(StatusCode, String), (StatusCode, String)> {
    Ok((StatusCode::OK, "Success!".to_string()))
}

async fn register_user(State(pool): State<PgPool>, Json(user): Json<User>) -> Result<(StatusCode, String), (StatusCode, String)> {
    if user.username == "" && user.password == "" {
        return Err((StatusCode::BAD_REQUEST, "Username or Password empty".to_string()));
    }

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

    // .execute(&pool)
    // .await
    // .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e.to_string())));

    tracing::info!("New user id is: {inserted_id}");

    let message = format!("User: {} registered!", user.username.clone());
    tracing::info!("{message}");

    let claims = Claims {
        id: inserted_id,
        username: user.username,
        exp: (chrono::Utc::now() + chrono::Duration::hours(24)).timestamp() as usize
    };

    let token = match encode(&Header::default(), &claims, &EncodingKey::from_secret("use-stringfrom-dot-env-here".as_ref())) {
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

        let token = match encode(&Header::default(), &claims, &EncodingKey::from_secret("use-stringfrom-dot-env-here".as_ref())) {
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

// #[derive(Clone)]
// struct TempDirState {
//     tempdir: Arc<TempDir>,
// }

// impl TempDirState {
//     fn try_new() -> Result<Self, color_eyre::Report>{
//         Ok(Self {
//             tempdir: Arc::new(tempfile::tempdir()?),
//         })
//     }

//     fn path(&self) -> &Path {
//         self.tempdir.path()
//     }
// }

async fn upload_file(State(pool): State<PgPool>, headers: HeaderMap, mut multipart: Multipart) -> Result<(StatusCode, String), (StatusCode, String)> {
    let mut token: String = "".to_string();
    if let Some(auth_header) = headers.get("Authorization") {
        if let Ok(auth_header_str) = auth_header.to_str() {
            if auth_header_str.starts_with("Bearer") {
                token = auth_header_str.trim_start_matches("Bearer ").to_string();
                // tracing::info!("Token: {}", token);
                match decode::<Claims>(&token, &DecodingKey::from_secret("use-stringfrom-dot-env-here".as_ref()), &Validation::default()) {
                    Ok(_) => {
                        // replace this with the decoded token
                        return Ok((StatusCode::OK, "return this if user logged in".to_string()));
                    },
                    Err(e) => {
                        tracing::error!("Error generating token {}", e);
                        return Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()));
                    }
                }
            }
        }
    }

    // Process file upload
    if let Some(field) = multipart.next_field().await.map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "Failed to process file upload".to_string(),
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
        sqlx::query!(
            "INSERT INTO files (id, filename, content_type, path) VALUES ($1, $2, $3, $4)",
            file_id,
            file_name,
            content_type,
            upload_path
        )
        .execute(&pool)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to save file metadata".to_string(),
            )
        })?;

        Ok(Json(UploadResponse {
            file_url: format!("/files/{}", file_id),
        }));
    } else {
        return Err((StatusCode::BAD_REQUEST, "No file provided".to_string()))
    };

    // let mut body = req.body_bytes().await?;
    

    // let test = tide::Body::from_file(file!()).await?;
    // let pool = req.state();
    // sqlx::query!(
    //     "INSERT INTO users (username, password) VALUES ($1, $2)",
    //     user.username,
    //     user.password
    // )
    // .execute(pool)
    // .await?;
    // let form = req.body_form().await?;
    // res.set_body(format!("User: {} uploaded {} files!", user.username.clone(), file_count));

    return Ok((StatusCode::OK, format!("request token: {}", token)));
}

async fn get_file_by_id(
    State(pool): State<PgPool>,
    Path(file_id): Path<Uuid>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    // 1. Get file metadata from database using ID
    let file_meta = sqlx::query!(
        "SELECT filename, content_type, path FROM files WHERE id = $1",
        file_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Database error".to_string()))?
    .ok_or((StatusCode::NOT_FOUND, "File not found".to_string()))?;

    // 2. Read file contents
    let mut file = File::open(&file_meta.path)
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
                format!("attachment; filename=\"{}\"", file_meta.filename),
            ),
        ],
        contents,
    ))
}


#[tokio::main]
async fn main() -> Result<(), color_eyre::Report> {
    color_eyre::install()?;

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect("postgres://postgres:postgres@localhost/postgres").await?;

    tracing::info!("Connected to database");

    tracing_subscriber::fmt()
        .with_target(false)
        .compact()
        .init();

    
    let app = Router::new()
        .route("/", get(health_check))
        .route("/register", post(register_user))
        .route("/login", post(login_user))
        .route("/upload", post(upload_file))
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
    
    // app.with(tide::log::LogMiddleware::new());

    // app.at("/").get(health_check);
    // app.at("/register").post(register_user);
    // app.at("/login").post(login_user);
    // app.at("/upload").put(upload_file);

    // app.listen("127.0.0.1:8000").await?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();

    // log::info!("Write Uploaded files to tempdir and if upload fails drop tempdir to delete files and try again");
    // log::info!("Or maybe just write file to upload dir and of chunk not whole then delete last chunk");
    // log::info!("Frontend loadingbar chunk number as progress");

    Ok(())
}

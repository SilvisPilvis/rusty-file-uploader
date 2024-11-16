use axum::{
    http::header,
    routing::{get, post},
    Router,
};
// use color_eyre;
use sqlx::postgres::PgPoolOptions;
use std::env;
use tower::ServiceBuilder;
use tower_http::cors::CorsLayer;
use tower_http::{
    cors::AllowCredentials,
    trace::{self, TraceLayer},
};

mod messages;
mod middleware;
mod routes; // pub use crate::routes;

// const API_PATH: &'static str = "http://127.0.0.1:3000";

#[tokio::main]
async fn main() -> Result<(), color_eyre::Report> {
    color_eyre::install()?;
    dotenvy::dotenv()?;
    // dotenv!();

    // Set RUST_LOG if not already set
    if std::env::var("RUST_LOG").is_err() {
        println!("Setting default RUST_LOG");
        std::env::set_var("RUST_LOG", "info");
    }

    // let pool;

    // if std::env::var("USE_ENV").is_err() {
    //     // std::env::set_var("RUST_LOG", "info");
    //     pool = PgPoolOptions::new()
    //         .max_connections(5)
    //         .connect(&env::var("DATABASE_URL")?).await?;
    // }else {
    //     pool = PgPoolOptions::new()
    //         .max_connections(5)
    //         .connect(&env::var("DATABASE_URL")?).await?;
    // }

    if std::env::var("API_URL").is_err() {
        println!("Setting default API_URL");
        std::env::set_var("API_URL", "http://127.0.0.1:3000");
    }

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&env::var("DATABASE_URL")?)
        .await?;

    // Migrate database
    // migrate(pool.clone()).await?;

    tracing::info!("Connected to database");

    tracing_subscriber::fmt()
        .with_target(false)
        .compact()
        .init();

    let trace_layer = TraceLayer::new_for_http()
        .make_span_with(trace::DefaultMakeSpan::new().level(tracing::Level::INFO))
        .on_request(trace::DefaultOnRequest::new().level(tracing::Level::INFO))
        .on_response(
            trace::DefaultOnResponse::new().level(tracing::Level::INFO), // .latency_unit(tower_http::classify::LatencyUnit::Micros),
        )
        .on_failure(trace::DefaultOnFailure::new().level(tracing::Level::ERROR));

    // Configure CORS to allow all origins
    let cors = CorsLayer::new()
        // .allow_origin(tower_http::cors::AllowOrigin::exact(
        //     "http://localhost:3000".parse().unwrap(),
        // ))
        // .allow_origin(tower_http::cors::AllowOrigin::exact(
        //     "http://127.0.0.1:3000".parse().unwrap(),
        // ))
        // .allow_origin(tower_http::cors::AllowOrigin::exact(
        //     "http://localhost:4321".parse().unwrap(),
        // ))
        // .allow_origin(tower_http::cors::AllowOrigin::exact(
        //     "http://127.0.0.1:4321".parse().unwrap(),
        // ))
        .allow_origin(tower_http::cors::AllowOrigin::exact(
            "http://127.0.0.1:4321".parse().unwrap(),
        ))
        // .allow_origin(Any)
        .allow_methods(vec![
            axum::http::Method::OPTIONS,
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::PUT,
            axum::http::Method::DELETE,
        ])
        // .allow_methods(Any)
        .allow_headers(vec![
            header::AUTHORIZATION,
            header::ACCEPT,
            header::CONTENT_TYPE,
        ])
        // .allow_headers(Any)
        .allow_credentials(AllowCredentials::yes());

    // Authenticated routes
    let auth_routes = Router::new()
        .route("/store/:store_id/upload", post(routes::upload_file))
        .route("/store/create", post(routes::create_store))
        .route("/store", get(routes::get_user_stores))
        .route("/store/:store_id/files", get(routes::get_files_from_store))
        .route("/store/:store_id/edit", post(routes::update_store))
        .route("/file/:file_id", get(routes::get_file_by_id_base64))
        .layer(
            ServiceBuilder::new()
                .layer(axum::middleware::from_fn(
                    middleware::authorization_middleware,
                ))
                .layer(cors.clone()),
        );

    // Public routes
    let app = Router::new()
        .route("/", get(routes::health_check))
        .route("/register", post(routes::register_user))
        .route("/login", post(routes::login_user))
        .route("/reset-password", post(routes::reset_password))
        .nest("", auth_routes)
        .with_state(pool)
        .layer(trace_layer)
        .layer(cors); // Apply CORS middleware
                      // Start server
                      // let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await.unwrap();
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app.into_make_service())
        .await
        .unwrap();

    // log::info!("Write Uploaded files to tempdir and if upload fails drop tempdir to delete files and try again");
    // log::info!("Or maybe just write file to upload dir and of chunk not whole then delete last chunk");
    // log::info!("Frontend loadingbar chunk number as progress");

    Ok(())
}

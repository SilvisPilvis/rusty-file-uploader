use axum::{extract::Request, middleware::Next, http::StatusCode};
use jsonwebtoken::{decode, DecodingKey, Validation};
use axum::response::IntoResponse;
use std::env;

use crate::messages;

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct Claims {
    pub id: i32,
    pub username: String,
    pub exp: usize,
}

pub async fn authorization_middleware(mut req: Request, next: Next) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or((StatusCode::UNAUTHORIZED, messages::create_json_response(messages::MessageType::Error, "No authorization token provided".to_string())))?;
        // .ok_or((StatusCode::UNAUTHORIZED, serde_json::to_string(&JsonError{ error: "No authorization token provided".to_string()})));

    let secert: String = env::var("SECRET").map_err(|_e| ((StatusCode::INTERNAL_SERVER_ERROR, messages::create_json_response(messages::MessageType::Error, "Failed to get SECRET from env".to_string()))))?;
    let decoding_key = DecodingKey::from_secret(secert.as_ref()); // Use your secret key here
    // let validation = Validation::new(Algorithm::HS384);
    let validation = Validation::default();

    let decoded_token = decode::<Claims>(&token, &decoding_key, &validation)
        .map_err(|_| (StatusCode::UNAUTHORIZED, messages::create_json_response(messages::MessageType::Error, "Token is expired".to_string())))?;

    // Insert the decoded token into request extensions
    req.extensions_mut().insert(decoded_token.claims);

    Ok(next.run(req).await)
}
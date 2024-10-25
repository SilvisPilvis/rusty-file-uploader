use axum::{extract::Request, middleware::Next, http::StatusCode};
use jsonwebtoken::{encode, decode, DecodingKey, Validation, Algorithm};
use axum::response::IntoResponse;

#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct Claims {
    id: i32,
    username: String,
    exp: usize,
}

pub async fn authorization_middleware(mut req: Request, next: Next) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or((StatusCode::UNAUTHORIZED, "{ 'error': 'No authorization token provided' }".to_string()))?;
        // .ok_or((StatusCode::UNAUTHORIZED, serde_json::to_string(&JsonError{ error: "No authorization token provided".to_string()})));

    let decoding_key = DecodingKey::from_secret(b"secret"); // Use your secret key here
    // let validation = Validation::new(Algorithm::HS384);
    let validation = Validation::default();

    let decoded_token = decode::<Claims>(&token, &decoding_key, &validation)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "{ 'error': 'No authorization token provided' }".to_string()))?;

    // Insert the decoded token into request extensions
    req.extensions_mut().insert(decoded_token.claims);

    Ok(next.run(req).await)
}
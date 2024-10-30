#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct JsonMessage {
    pub message: String,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct JsonError {
    pub error: String,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct JsonToken {
    pub token: String,
}

pub enum MessageType {
    Message,
    Error,
    Token,
}

pub fn create_json_response(message_type: MessageType, message: String) -> String {
    match message_type {
        MessageType::Message => {
            let json_message = JsonMessage { message };
            serde_json::to_string(&json_message).unwrap()
        }
        MessageType::Error => {
            let json_error = JsonError { error: message };
            serde_json::to_string(&json_error).unwrap()
        }
        MessageType::Token => {
            let json_error = JsonToken { token: message };
            serde_json::to_string(&json_error).unwrap()
        }
    }
}
//! Control-channel messages (JSON payloads on `Channel::Control`).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum ControlMessage {
    #[serde(rename_all = "camelCase")]
    Exec {
        command_line: String,
        #[serde(default)]
        env: Vec<String>,
        #[serde(default)]
        cwd: Option<String>,
        #[serde(default)]
        timeout_ms: Option<u64>,
    },
    Exit {
        code: i32,
    },
    Error {
        message: String,
    },
}

pub fn encode_control(message: &ControlMessage) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(message)
}

pub fn decode_control(bytes: &[u8]) -> Result<ControlMessage, serde_json::Error> {
    serde_json::from_slice(bytes)
}

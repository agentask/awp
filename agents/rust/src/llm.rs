//! A minimal xAI Grok client: plain `reqwest` against the OpenAI-compatible
//! `/v1/chat/completions` endpoint. No LLM SDK dependency — this repo's
//! general minimal-dependency ethos (see root `CLAUDE.md`: "no cgo
//! anywhere", "do NOT pull a [...] library") applies just as well to a
//! single HTTP call like this one. The Rust counterpart to
//! `agents/go/llm.go`.

use serde::{Deserialize, Serialize};

const XAI_ENDPOINT: &str = "https://api.x.ai/v1/chat/completions";

/// One `{role, content}` turn in a Grok chat completion request/response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

#[derive(Debug, thiserror::Error)]
pub enum LlmError {
    #[error("llm: request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("llm: xAI returned status {0}: {1}")]
    BadStatus(u16, String),
    #[error("llm: parse response: {0}")]
    Parse(String),
    #[error("llm: no choices in response: {0}")]
    NoChoices(String),
}

#[derive(Serialize)]
struct ChatCompletionRequest<'a> {
    model: &'a str,
    messages: Vec<ChatMessage>,
    temperature: f64,
}

#[derive(Deserialize)]
struct ChatCompletionResponse {
    #[serde(default)]
    choices: Vec<Choice>,
}

#[derive(Deserialize)]
struct Choice {
    message: ChatMessage,
}

/// Calls the xAI chat completions endpoint.
pub struct GrokClient {
    api_key: String,
    model: String,
    http: reqwest::Client,
}

impl GrokClient {
    pub fn new(api_key: impl Into<String>, model: impl Into<String>) -> Self {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .expect("reqwest client builds");
        Self {
            api_key: api_key.into(),
            model: model.into(),
            http,
        }
    }

    /// Sends `system_prompt` plus `history` (prior turns) plus a final user
    /// message with `user_content`, and returns the model's reply text.
    pub async fn complete(
        &self,
        system_prompt: &str,
        history: &[ChatMessage],
        user_content: &str,
    ) -> Result<String, LlmError> {
        let mut messages = Vec::with_capacity(history.len() + 2);
        messages.push(ChatMessage {
            role: "system".to_string(),
            content: system_prompt.to_string(),
        });
        messages.extend_from_slice(history);
        messages.push(ChatMessage {
            role: "user".to_string(),
            content: user_content.to_string(),
        });

        let body = ChatCompletionRequest {
            model: &self.model,
            messages,
            temperature: 0.7,
        };

        let resp = self
            .http
            .post(XAI_ENDPOINT)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await?;
        let status = resp.status();
        let raw = resp.text().await?;
        if !status.is_success() {
            return Err(LlmError::BadStatus(status.as_u16(), raw));
        }

        let out: ChatCompletionResponse =
            serde_json::from_str(&raw).map_err(|e| LlmError::Parse(e.to_string()))?;
        out.choices
            .into_iter()
            .next()
            .map(|c| c.message.content)
            .ok_or_else(|| LlmError::NoChoices(raw))
    }
}

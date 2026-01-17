use axum::{
    Router,
    routing::post,
    extract::{Path, State},
    body::Bytes,
    http::{StatusCode, HeaderMap},
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::path::PathBuf;
use std::sync::Arc;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
struct AppConfig {
    webhook_secret: String,
    hooks_dir: PathBuf,
    port: String,
}

impl AppConfig {
    fn from_env() -> Self {
        let webhook_secret = std::env::var("WEBHOOK_SECRET")
            .expect("WEBHOOK_SECRET environment variable must be set");

        let hooks_dir = std::env::var("HOOKS_DIR")
            .unwrap_or_else(|_| "./hooks".to_string());
        let hooks_dir = PathBuf::from(hooks_dir)
            .canonicalize().expect("Unable to canonicalize hooks dir");
        if !hooks_dir.is_dir() {
            panic!("Hooks dir does not exist or is not a directory");
        }

        let port = std::env::var("PORT")
            .unwrap_or_else(|_| "3000".to_string());

        Self {
            webhook_secret,
            hooks_dir,
            port,
        }
    }
}

#[tokio::main]
async fn main() {
    let config = Arc::new(AppConfig::from_env());
    let addr = format!("0.0.0.0:{}", &config.port);

    let app = Router::new()
        .route("/webhook/{project}", post(webhook_handler))
        .with_state(config);

    println!("Listening on {}", &addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();

    axum::serve(listener, app).await.unwrap();
}

fn verify_signature(secret: &str, signature_header: &str, payload: &[u8]) -> bool {
    let parts: Vec<&str> = signature_header.split('=').collect();
    if parts.len() != 2 || parts[0] != "sha256" {
        return false;
    }

    let sig_hex = parts[1];
    let Ok(expected_sig) = hex::decode(sig_hex) else {
        return false;
    };

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(payload);

    mac.verify_slice(&expected_sig).is_ok()
}

async fn webhook_handler(
    State(config): State<Arc<AppConfig>>,
    Path(project): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, StatusCode> {
    // Validate project name - prevent path traversal
    if project.contains("..") || project.contains('/')  || project.contains('%') || project.contains('\\') || project.starts_with('.') {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Get signature from header
    let signature = headers
        .get("x-hub-signature-256")
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // Verify signature
    if !verify_signature(&config.webhook_secret, signature, &body) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Check if hook script exists
    let hook_path = config.hooks_dir
        .join(&project)
        .canonicalize()
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    // Second path traversal sanity check
    if !hook_path.starts_with(&config.hooks_dir) {
        return Err(StatusCode::BAD_REQUEST);
    }

    if !hook_path.exists() {
        return Err(StatusCode::NOT_FOUND);
    }

    // Execute hook script with security restrictions
    execute_hook(&hook_path).await?;

    Ok(StatusCode::OK)
}

async fn execute_hook(script_path: &PathBuf) -> Result<(), StatusCode> {
    println!("Executing '{:?}'", script_path);
    // TODO: sandbox hooks and only copy output
    let output = tokio::process::Command::new(script_path)
        .output()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if !output.status.success() {
        eprintln!("Hook failed: {:?}", output);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    Ok(())
}


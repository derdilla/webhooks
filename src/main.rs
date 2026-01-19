use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::post,
    Router,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::os::unix::prelude::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use landlock::{RulesetCreated, RulesetError};

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
struct AppConfig {
    webhook_secret: String,
    hooks_dir: PathBuf,
    port: String,
}

const ENV_WEBHOOK_SECRET: &str = "WEBHOOK_SECRET";
const ENV_HOOKS_DIR: &str = "HOOKS_DIR";
const ENV_PORT: &str = "PORT";

impl AppConfig {
    fn from_env() -> Self {
        let webhook_secret = std::env::var(ENV_WEBHOOK_SECRET)
            .expect("WEBHOOK_SECRET environment variable must be set");

        let hooks_dir = std::env::var(ENV_HOOKS_DIR)
            .unwrap_or_else(|_| "./hooks".to_string());
        let hooks_dir = PathBuf::from(hooks_dir)
            .canonicalize().expect("Unable to canonicalize hooks dir");
        if !hooks_dir.is_dir() {
            panic!("Hooks dir does not exist or is not a directory");
        }

        let port = std::env::var(ENV_PORT)
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

    // Get signature from the header
    let signature = headers
        .get("x-hub-signature-256")
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // Verify signature
    if !verify_signature(&config.webhook_secret, signature, &body) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Check if the hook script exists
    let hook_path = config.hooks_dir
        .join(&project)
        .canonicalize();

    println!("Checking {:?}, {:?}", hook_path, config.hooks_dir
        .join(&project));
    let hook_path = hook_path.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Second path traversal sanity check
    if !hook_path.starts_with(&config.hooks_dir) {
        return Err(StatusCode::BAD_REQUEST);
    }

    if !hook_path.exists() {
        return Err(StatusCode::NOT_FOUND);
    }

    // Execute the hook script in a non-blocking fashion with sandboxing
    execute_hook(hook_path)?;

    Ok(StatusCode::OK)
}

fn execute_hook(script_path: PathBuf) -> Result<(), StatusCode> {
    println!("Executing '{:?}'", &script_path);

    let workdir = tempfile::tempdir()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut command = Command::new(script_path);
    let command = (&mut command)
        .env_remove(ENV_WEBHOOK_SECRET)
        .env_remove(ENV_HOOKS_DIR)
        .env_remove(ENV_PORT)
        .env("TMPDIR", &workdir.path());

    // Only allow write to workdir_path and static pages
    let allowed_path = PathBuf::from(workdir.path());

    // SAFETY: pre_exec runs in the child process after fork() but before exec().
    // Out code is fine there since we only call standard Linux system calls to
    // configure permissions so the process can do less unexpected things.
    unsafe {
        command.pre_exec(move || {
            libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
            let ruleset = create_ruleset(allowed_path.clone())
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR);
            if let Ok(ruleset) = ruleset {
                if !ruleset.restrict_self().is_ok() {
                    eprintln!("Restriction check failed");
                }
            } else {
                eprintln!("Failed to create ruleset");
            };

            Ok(())
        });
    }

    let mut proc = command
        .spawn()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    tokio::task::spawn(async move {
        _ = proc.wait();
        workdir.close().unwrap();
    });

    Ok(())
}

fn create_ruleset(workdir: PathBuf) -> Result<RulesetCreated, RulesetError> {
    use landlock::{path_beneath_rules, Access, AccessFs, Ruleset, RulesetAttr, RulesetCreatedAttr, ABI};

    let abi = ABI::V6;
    Ruleset::default()
        .handle_access(AccessFs::from_all(abi))?
        .create()?
        .add_rules(path_beneath_rules(&["/"], AccessFs::from_read(abi)))?
        .add_rules(path_beneath_rules(&["/www"], AccessFs::from_all(abi)))?
        .add_rules(path_beneath_rules(&[workdir], AccessFs::from_all(abi)))
}


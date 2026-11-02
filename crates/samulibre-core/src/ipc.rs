use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tracing::{error, info, warn};

/// Mensaje de Petición IPC entre Clientes (GUI/CLI) y el Demonio (samulibred)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcRequest {
    pub id: String,
    pub action: String,
    pub payload: Option<serde_json::Value>,
}

/// Respuesta IPC generada por el Demonio
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcResponse {
    pub id: String,
    pub success: bool,
    pub data: Option<serde_json::Value>,
    pub error: Option<String>,
}

impl IpcResponse {
    pub fn ok(id: &str, data: serde_json::Value) -> Self {
        Self {
            id: id.to_string(),
            success: true,
            data: Some(data),
            error: None,
        }
    }

    pub fn err(id: &str, msg: impl Into<String>) -> Self {
        Self {
            id: id.to_string(),
            success: false,
            data: None,
            error: Some(msg.into()),
        }
    }
}

/// Resuelve la ruta canónica y segura del UNIX Domain Socket
pub fn resolve_ipc_socket_path() -> PathBuf {
    #[cfg(unix)]
    {
        // 1. Ruta privilegiada de sistema (modo daemon root / systemd)
        let sys_path = PathBuf::from("/run/samulibre/samulibre.sock");
        if sys_path.exists() {
            return sys_path;
        }

        // 2. Ruta XDG_RUNTIME_DIR del usuario (ej: /run/user/1000/samulibre.sock)
        if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
            let user_sock = PathBuf::from(runtime_dir).join("samulibre.sock");
            return user_sock;
        }

        // 3. Fallback a directorio seguro en /tmp
        let uid = unsafe { libc::getuid() };
        PathBuf::from(format!("/tmp/samulibre_{}.sock", uid))
    }
    #[cfg(not(unix))]
    {
        PathBuf::from(r"\\.\pipe\samulibre_ipc")
    }
}

/// Cliente IPC para comunicarse con el Demonio samulibred vía UNIX Domain Socket
pub struct UnixSocketClient {
    socket_path: PathBuf,
}

impl UnixSocketClient {
    pub fn new(socket_path: impl AsRef<Path>) -> Self {
        Self {
            socket_path: socket_path.as_ref().to_path_buf(),
        }
    }

    /// Conecta y envía una petición JSON-RPC al Demonio, esperando la respuesta
    pub async fn send_request(&self, request: &IpcRequest) -> Result<IpcResponse> {
        if !self.socket_path.exists() {
            return Err(anyhow!(
                "El demonio de seguridad samulibred no está activo en: {}",
                self.socket_path.display()
            ));
        }

        let stream = UnixStream::connect(&self.socket_path).await?;
        let (reader, mut writer) = stream.into_split();

        let mut req_str = serde_json::to_string(request)?;
        req_str.push('\n');
        writer.write_all(req_str.as_bytes()).await?;
        writer.flush().await?;

        let mut buf_reader = BufReader::new(reader);
        let mut line = String::new();
        buf_reader.read_line(&mut line).await?;

        let response: IpcResponse = serde_json::from_str(&line)?;
        Ok(response)
    }

    pub fn is_daemon_available(&self) -> bool {
        self.socket_path.exists()
    }
}

/// Servidor IPC para el Demonio samulibred
pub struct UnixSocketServer {
    socket_path: PathBuf,
    listener: Option<UnixListener>,
}

impl UnixSocketServer {
    pub fn bind(socket_path: impl AsRef<Path>) -> Result<Self> {
        let path = socket_path.as_ref().to_path_buf();

        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o755));
            }
        }

        // Si existe un socket huérfano de una ejecución previa, limpiarlo de forma segura
        if path.exists() {
            let _ = fs::remove_file(&path);
        }

        let listener = UnixListener::bind(&path)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Permisos 0666 para socket de usuario o 0660 para grupo samulibre
            let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o666));
        }

        info!("Servidor IPC UNIX Domain Socket escuchando en: {}", path.display());

        Ok(Self {
            socket_path: path,
            listener: Some(listener),
        })
    }

    /// Bucle principal del servidor que despacha peticiones mediante un handler de lógica
    pub async fn run_server<F, Fut>(&mut self, handler: F) -> Result<()>
    where
        F: Fn(IpcRequest) -> Fut + Send + Sync + 'static + Clone,
        Fut: std::future::Future<Output = IpcResponse> + Send + 'static,
    {
        let listener = self.listener.take().ok_or_else(|| anyhow!("Listener ya consumido"))?;

        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    let h = handler.clone();
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_connection(stream, h).await {
                            warn!("Error procesando cliente IPC: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("Error aceptando conexión en UNIX socket: {}", e);
                    break;
                }
            }
        }

        Ok(())
    }

    async fn handle_connection<F, Fut>(stream: UnixStream, handler: F) -> Result<()>
    where
        F: Fn(IpcRequest) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = IpcResponse> + Send + 'static,
    {
        let (reader, mut writer) = stream.into_split();
        let mut buf_reader = BufReader::new(reader);
        let mut line = String::new();

        while buf_reader.read_line(&mut line).await? > 0 {
            let req_res = serde_json::from_str::<IpcRequest>(&line);
            let resp = match req_res {
                Ok(req) => handler(req).await,
                Err(e) => IpcResponse::err("unknown", format!("Mensaje JSON inválido: {}", e)),
            };

            let mut resp_str = serde_json::to_string(&resp)?;
            resp_str.push('\n');
            writer.write_all(resp_str.as_bytes()).await?;
            writer.flush().await?;
            line.clear();
        }

        Ok(())
    }
}

impl Drop for UnixSocketServer {
    fn drop(&mut self) {
        if self.socket_path.exists() {
            let _ = fs::remove_file(&self.socket_path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_unix_ipc_client_server_lifecycle() {
        let temp_dir = std::env::temp_dir().join(format!("samu_ipc_test_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);
        let sock_path = temp_dir.join("test.sock");

        let mut server = UnixSocketServer::bind(&sock_path).expect("Failed to bind server");

        // Spawn del servidor en background
        tokio::spawn(async move {
            let handler = |req: IpcRequest| async move {
                match req.action.as_str() {
                    "ping" => IpcResponse::ok(&req.id, serde_json::json!({"status": "pong"})),
                    "get_version" => IpcResponse::ok(&req.id, serde_json::json!({"version": "2.0.32"})),
                    _ => IpcResponse::err(&req.id, "Acción desconocida"),
                }
            };
            let _ = server.run_server(handler).await;
        });

        // Dar un instante para que el listener comience a escuchar
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let client = UnixSocketClient::new(&sock_path);
        assert!(client.is_daemon_available());

        // Test PING
        let req1 = IpcRequest {
            id: "req-1".to_string(),
            action: "ping".to_string(),
            payload: None,
        };
        let resp1 = client.send_request(&req1).await.expect("IPC request failed");
        assert!(resp1.success);
        assert_eq!(resp1.data.unwrap()["status"], "pong");

        // Test GET_VERSION
        let req2 = IpcRequest {
            id: "req-2".to_string(),
            action: "get_version".to_string(),
            payload: None,
        };
        let resp2 = client.send_request(&req2).await.expect("IPC request failed");
        assert!(resp2.success);
        assert_eq!(resp2.data.unwrap()["version"], "2.0.32");

        let _ = fs::remove_dir_all(&temp_dir);
    }
}

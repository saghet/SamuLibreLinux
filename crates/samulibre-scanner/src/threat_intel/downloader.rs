use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::time::Duration;
use tracing::debug;

pub const DEFAULT_TIMEOUT_SECS: u64 = 8;
pub const MAX_DOWNLOAD_BYTES: usize = 20 * 1024 * 1024; // 20 MB límite máximo

/// Descargador seguro con validación estricta de transporte TLS, tamaño y hash
#[derive(Debug, Clone)]
pub struct SecureDownloader {
    timeout: Duration,
    max_bytes: usize,
    user_agent: String,
}

impl Default for SecureDownloader {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            max_bytes: MAX_DOWNLOAD_BYTES,
            user_agent: format!(
                "SamuLibre-ThreatIntel/{} (Linux; Security Scanner; +https://samulibre.org)",
                env!("CARGO_PKG_VERSION")
            ),
        }
    }
}

pub struct DownloadResponse {
    pub bytes: Vec<u8>,
    pub sha256_hash: String,
    pub status_code: u16,
    pub content_type: Option<String>,
}

impl SecureDownloader {
    pub fn new(timeout_secs: u64, max_bytes: usize) -> Self {
        Self {
            timeout: Duration::from_secs(timeout_secs),
            max_bytes,
            user_agent: format!(
                "SamuLibre-ThreatIntel/{} (Linux; Security Scanner)",
                env!("CARGO_PKG_VERSION")
            ),
        }
    }

    /// Realiza una petición GET segura sobre HTTPS
    pub fn get(&self, url: &str) -> Result<DownloadResponse> {
        if !url.starts_with("https://") && !url.starts_with("http://127.0.0.1") && !url.starts_with("http://localhost") {
            bail!("Protocolo no seguro rechazado: Se exige HTTPS obligatorio para feeds de inteligencia ({})", url);
        }

        debug!("Consultando feed seguro: {}", url);

        let mut config = ureq::Agent::config_builder();
        config = config.timeout_global(Some(self.timeout));
        let agent = config.build().new_agent();

        let response = match agent.get(url)
            .header("User-Agent", &self.user_agent)
            .header("Accept", "application/json, text/plain, */*")
            .call() {
                Ok(res) => res,
                Err(err) => {
                    bail!("Fallo de conexión al proveedor '{}': {}", url, err);
                }
            };

        let status = response.status().as_u16();
        if status == 429 {
            bail!("Límite de tasa alcanzado (HTTP 429 Too Many Requests) en '{}'", url);
        }
        if status < 200 || status >= 300 {
            bail!("El servidor de feed respondió con código de error HTTP {}: '{}'", status, url);
        }

        let content_type = response.headers().get("content-type").and_then(|v| v.to_str().ok()).map(|s| s.to_string());

        let mut reader = response.into_body().into_reader();
        let mut buffer = Vec::new();
        let mut total_read = 0;
        let mut chunk = [0u8; 8192];

        use std::io::Read;
        loop {
            let n = reader.read(&mut chunk).context("Error leyendo stream de datos del proveedor")?;
            if n == 0 {
                break;
            }
            total_read += n;
            if total_read > self.max_bytes {
                bail!(
                    "Tamaño de descarga excedido ({} bytes > límite {} bytes). Posible DoS o feed malformado.",
                    total_read,
                    self.max_bytes
                );
            }
            buffer.extend_from_slice(&chunk[..n]);
        }

        let sha256_hash = hex::encode(Sha256::digest(&buffer));
        Ok(DownloadResponse {
            bytes: buffer,
            sha256_hash,
            status_code: status,
            content_type,
        })
    }

    /// Realiza una petición POST segura (JSON o Form)
    pub fn post_json(&self, url: &str, body: &serde_json::Value) -> Result<DownloadResponse> {
        if !url.starts_with("https://") && !url.starts_with("http://127.0.0.1") && !url.starts_with("http://localhost") {
            bail!("Protocolo no seguro rechazado: Se exige HTTPS obligatorio para feeds de inteligencia ({})", url);
        }

        debug!("Enviando consulta POST a: {}", url);

        let mut config = ureq::Agent::config_builder();
        config = config.timeout_global(Some(self.timeout));
        let agent = config.build().new_agent();

        let json_body = serde_json::to_vec(body)?;

        let response = match agent.post(url)
            .header("User-Agent", &self.user_agent)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .send(&json_body) {
                Ok(res) => res,
                Err(err) => {
                    bail!("Fallo en petición POST a '{}': {}", url, err);
                }
            };

        let status = response.status().as_u16();
        if status == 429 {
            bail!("Límite de tasa alcanzado (HTTP 429 Too Many Requests) en '{}'", url);
        }
        if status < 200 || status >= 300 {
            bail!("El servidor de feed respondió con código de error HTTP {}: '{}'", status, url);
        }

        let content_type = response.headers().get("content-type").and_then(|v| v.to_str().ok()).map(|s| s.to_string());
        let mut reader = response.into_body().into_reader();
        let mut buffer = Vec::new();
        let mut total_read = 0;
        let mut chunk = [0u8; 8192];

        use std::io::Read;
        loop {
            let n = reader.read(&mut chunk).context("Error leyendo stream de datos del proveedor")?;
            if n == 0 {
                break;
            }
            total_read += n;
            if total_read > self.max_bytes {
                bail!(
                    "Tamaño de descarga excedido ({} bytes > límite {} bytes).",
                    total_read,
                    self.max_bytes
                );
            }
            buffer.extend_from_slice(&chunk[..n]);
        }

        let sha256_hash = hex::encode(Sha256::digest(&buffer));
        Ok(DownloadResponse {
            bytes: buffer,
            sha256_hash,
            status_code: status,
            content_type,
        })
    }

    /// Realiza una petición POST segura codificada en URL (form-urlencoded)
    pub fn post_form(&self, url: &str, form_data: &[(&str, &str)]) -> Result<DownloadResponse> {
        if !url.starts_with("https://") && !url.starts_with("http://127.0.0.1") && !url.starts_with("http://localhost") {
            bail!("Protocolo no seguro rechazado: Se exige HTTPS obligatorio ({})", url);
        }

        let mut config = ureq::Agent::config_builder();
        config = config.timeout_global(Some(self.timeout));
        let agent = config.build().new_agent();

        let encoded = form_data
            .iter()
            .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
            .collect::<Vec<_>>()
            .join("&");

        let response = match agent.post(url)
            .header("User-Agent", &self.user_agent)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Accept", "application/json, text/plain, */*")
            .send(encoded.as_bytes()) {
                Ok(res) => res,
                Err(err) => {
                    bail!("Fallo en petición POST (form) a '{}': {}", url, err);
                }
            };

        let status = response.status().as_u16();
        if status == 429 {
            bail!("Límite de tasa alcanzado (HTTP 429 Too Many Requests) en '{}'", url);
        }
        if status < 200 || status >= 300 {
            bail!("El servidor de feed respondió con código de error HTTP {}: '{}'", status, url);
        }

        let content_type = response.headers().get("content-type").and_then(|v| v.to_str().ok()).map(|s| s.to_string());
        let mut reader = response.into_body().into_reader();
        let mut buffer = Vec::new();
        let mut total_read = 0;
        let mut chunk = [0u8; 8192];

        use std::io::Read;
        loop {
            let n = reader.read(&mut chunk).context("Error leyendo stream")?;
            if n == 0 {
                break;
            }
            total_read += n;
            if total_read > self.max_bytes {
                bail!("Tamaño de descarga excedido ({} bytes > {} bytes)", total_read, self.max_bytes);
            }
            buffer.extend_from_slice(&chunk[..n]);
        }

        let sha256_hash = hex::encode(Sha256::digest(&buffer));
        Ok(DownloadResponse {
            bytes: buffer,
            sha256_hash,
            status_code: status,
            content_type,
        })
    }
}

// Módulo interno simple de urlencoding para evitar dependencias externas innecesarias
mod urlencoding {
    pub fn encode(input: &str) -> String {
        let mut encoded = String::with_capacity(input.len());
        for byte in input.bytes() {
            match byte {
                b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    encoded.push(byte as char);
                }
                b' ' => encoded.push('+'),
                _ => {
                    encoded.push_str(&format!("%{:02X}", byte));
                }
            }
        }
        encoded
    }
}

//! 出站代理（env `RITHMIC_PROXY`）：socks5 / socks5h / http / https 四种隧道。
//!
//! 设计与 binance-sdk 补丁同构：底层流统一装箱（[`IoStream`] 合并 trait），
//! 直连 / socks 隧道 / CONNECT 隧道先拿到裸流，TLS + WebSocket 握手照旧交给
//! tokio-tungstenite。`https` 代理先与代理做 TLS（native-tls 系统根证书），
//! 再发 CONNECT，形成 TLS-in-TLS——外层护代理链路，内层护 Rithmic 会话。

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, tungstenite::Error as WsError};

/// WS 底层 IO 流的合并 trait——直连 TcpStream / socks5 隧道 / http(s) CONNECT 隧道统一装箱形态。
/// Debug 进 supertrait：让 `Box<dyn IoStream>` 及其上的 WsStream 保持 Debug
/// （下游 PlantCore 的 Debug 派生链依赖它）。
pub trait IoStream: AsyncRead + AsyncWrite + Send + Unpin + std::fmt::Debug {}
impl<T> IoStream for T where T: AsyncRead + AsyncWrite + Send + Unpin + std::fmt::Debug {}

pub type BoxedIoStream = Box<dyn IoStream>;

/// Rithmic WebSocket 连接的统一流类型（可能经由代理隧道）。
pub(crate) type WsStream = WebSocketStream<MaybeTlsStream<BoxedIoStream>>;

/// 出站代理规格。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxySpec {
    /// `socks5`（本地 DNS）| `socks5h`（代理侧 DNS）| `http` | `https`
    pub scheme: String,
    pub host: String,
    pub port: u16,
    /// 代理鉴权：http = Basic 认证头；socks5 = 用户名密码握手
    pub username: Option<String>,
    pub password: Option<String>,
}

/// 解析代理 URL。形态：`socks5h://user:pass@host:port` / `http://host:port` /
/// `https://host:port`；裸 `host:port` 默认按 `socks5h`（代理侧解析 DNS，防本地污染）。
pub fn parse_proxy_url(raw: &str) -> Result<ProxySpec, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("代理地址为空".to_owned());
    }
    let (scheme, rest) = match raw.split_once("://") {
        Some((s, r)) => (s.to_ascii_lowercase(), r),
        None => ("socks5h".to_owned(), raw),
    };
    if !matches!(scheme.as_str(), "socks5" | "socks5h" | "http" | "https") {
        return Err(format!(
            "不支持的代理协议: {scheme}（支持 socks5/socks5h/http/https）"
        ));
    }
    // userinfo 与 host:port 分离（rfind：密码里允许出现 @）
    let (userinfo, hostport) = match rest.rsplit_once('@') {
        Some((u, h)) => (Some(u), h),
        None => (None, rest),
    };
    // IPv6 [::1]:1080 与普通 host:port 都按最后一个冒号切端口
    let (host, port) = hostport
        .rsplit_once(':')
        .ok_or_else(|| format!("代理地址缺少端口: {raw}"))?;
    let host = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    if host.is_empty() {
        return Err(format!("代理地址缺少 host: {raw}"));
    }
    let port = port
        .parse::<u16>()
        .map_err(|_| format!("代理端口非法: {raw}"))?;
    let (username, password) = userinfo
        .map(|u| match u.split_once(':') {
            Some((user, pass)) => (Some(user.to_owned()), Some(pass.to_owned())),
            None => (Some(u.to_owned()), None),
        })
        .unwrap_or((None, None));
    Ok(ProxySpec {
        scheme,
        host,
        port,
        username,
        password,
    })
}

/// 从 `RITHMIC_PROXY` 读取出站代理；未设置或为空 = 不代理（直连）。
/// 值非法时记日志并直连降级（不阻断连接，错误在日志里可见）。
pub fn proxy_from_env() -> Option<ProxySpec> {
    let raw = std::env::var("RITHMIC_PROXY").ok()?;
    if raw.trim().is_empty() {
        return None;
    }
    match parse_proxy_url(&raw) {
        Ok(spec) => Some(spec),
        Err(e) => {
            tracing::warn!("RITHMIC_PROXY 非法，已忽略并直连: {e}");
            None
        }
    }
}

fn hs(msg: String) -> WsError {
    WsError::Io(std::io::Error::other(msg))
}

/// 按目标 URI 与代理规格建立底层流：直连 / socks5(socks5h) 隧道 / http(s) CONNECT 隧道。
pub async fn connect_stream_via(
    uri: &tokio_tungstenite::tungstenite::http::Uri,
    proxy: Option<&ProxySpec>,
) -> Result<BoxedIoStream, WsError> {
    let host = uri
        .host()
        .ok_or_else(|| hs("ws url 缺少 host".to_owned()))?
        .to_owned();
    let port = uri.port_u16().unwrap_or(match uri.scheme_str() {
        Some("wss") => 443,
        _ => 80,
    });

    match proxy {
        None => {
            let tcp = TcpStream::connect((host.as_str(), port))
                .await
                .map_err(|e| hs(format!("直连 {host}:{port} 失败: {e}")))?;
            // 上游建连恒设 TCP_NODELAY（RSSL 低延迟语义），直连路径保持对等
            let _ = tcp.set_nodelay(true);
            Ok(Box::new(tcp))
        }
        Some(spec) => match spec.scheme.as_str() {
            "socks5" | "socks5h" => socks_tunnel(spec, &host, port).await,
            "http" | "https" => http_connect_tunnel(spec, &host, port).await,
            other => Err(hs(format!("不支持的代理协议: {other}"))),
        },
    }
}

/// socks5/socks5h 隧道：握手完成后取回裸 TcpStream（TLS + WS 交给 tungstenite）。
async fn socks_tunnel(spec: &ProxySpec, host: &str, port: u16) -> Result<BoxedIoStream, WsError> {
    // socks5h：域名交给代理解析（防本地 DNS 污染）；socks5：本地解析
    let target = if spec.scheme == "socks5h" {
        tokio_socks::TargetAddr::Domain(std::borrow::Cow::Owned(host.to_owned()), port)
    } else {
        let addr = tokio::net::lookup_host((host, port))
            .await
            .map_err(|e| hs(format!("解析 {host}:{port} 失败: {e}")))?
            .next()
            .ok_or_else(|| hs(format!("解析 {host}:{port} 无结果")))?;
        tokio_socks::TargetAddr::Ip(addr)
    };
    let proxy = (spec.host.as_str(), spec.port);
    let stream = match spec.username.as_deref() {
        Some(u) => {
            tokio_socks::tcp::socks5::Socks5Stream::connect_with_password(
                proxy,
                target,
                u,
                spec.password.as_deref().unwrap_or(""),
            )
            .await
        }
        None => tokio_socks::tcp::socks5::Socks5Stream::connect(proxy, target).await,
    }
    .map_err(|e| {
        hs(format!(
            "socks5 代理 {}:{} 连接失败: {e}",
            spec.host, spec.port
        ))
    })?;
    let tcp = stream.into_inner();
    let _ = tcp.set_nodelay(true);
    Ok(Box::new(tcp))
}

/// http(s) CONNECT 隧道：向代理发 CONNECT，2xx 应答后该流即为目标隧道。
async fn http_connect_tunnel(
    spec: &ProxySpec,
    host: &str,
    port: u16,
) -> Result<BoxedIoStream, WsError> {
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine as _;

    let tcp = TcpStream::connect((spec.host.as_str(), spec.port))
        .await
        .map_err(|e| {
            hs(format!(
                "代理 {}:{} TCP 连接失败: {e}",
                spec.host, spec.port
            ))
        })?;
    let _ = tcp.set_nodelay(true);
    let mut stream: BoxedIoStream = Box::new(tcp);
    if spec.scheme == "https" {
        stream = tls_wrap_to_proxy(spec, stream).await?;
    }

    // CONNECT 请求（可选 Basic 代理认证）
    let auth = match spec.username {
        Some(ref u) => format!(
            "Proxy-Authorization: Basic {}\r\n",
            BASE64.encode(format!("{}:{}", u, spec.password.as_deref().unwrap_or("")))
        ),
        None => String::new(),
    };
    let req = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n{auth}\r\n");
    stream
        .write_all(req.as_bytes())
        .await
        .map_err(|e| hs(format!("发送 CONNECT 失败: {e}")))?;

    // 读到响应头结束，判状态码
    let mut buf: Vec<u8> = Vec::with_capacity(512);
    let mut chunk = [0u8; 512];
    loop {
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(|e| hs(format!("读 CONNECT 应答失败: {e}")))?;
        if n == 0 {
            return Err(hs("代理在应答 CONNECT 前断开".to_owned()));
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(status) = parse_connect_status(&buf) {
            if (200..300).contains(&status) {
                tracing::debug!("CONNECT 隧道已建立（代理应答 {status}）");
                return Ok(stream);
            }
            return Err(hs(format!("代理拒绝 CONNECT（状态 {status}）")));
        }
        if buf.len() > 16 * 1024 {
            return Err(hs("代理 CONNECT 应答头超长".to_owned()));
        }
    }
}

/// 从已缓冲字节里解析 CONNECT 应答状态码；响应头未完结时返回 None。
pub fn parse_connect_status(buf: &[u8]) -> Option<u16> {
    let end = buf.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = std::str::from_utf8(&buf[..end]).ok()?;
    head.lines().next()?.split_whitespace().nth(1)?.parse().ok()
}

/// https 代理：与代理之间先做 TLS（系统根证书），隧道内容不受影响。
async fn tls_wrap_to_proxy(
    spec: &ProxySpec,
    tcp: BoxedIoStream,
) -> Result<BoxedIoStream, WsError> {
    let connector = native_tls::TlsConnector::new()
        .map_err(|e| hs(format!("构造代理 TLS connector 失败: {e}")))?;
    let tls = tokio_native_tls::TlsConnector::from(connector)
        .connect(spec.host.as_str(), tcp)
        .await
        .map_err(|e| hs(format!("与代理 {} 的 TLS 握手失败: {e}", spec.host)))?;
    Ok(Box::new(tls))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_socks5h_with_userinfo() {
        let spec = parse_proxy_url("socks5h://user:pass@127.0.0.1:1080").unwrap();
        assert_eq!(
            spec,
            ProxySpec {
                scheme: "socks5h".to_owned(),
                host: "127.0.0.1".to_owned(),
                port: 1080,
                username: Some("user".to_owned()),
                password: Some("pass".to_owned()),
            }
        );
    }

    #[test]
    fn bare_host_defaults_to_socks5h() {
        let spec = parse_proxy_url("127.0.0.1:1080").unwrap();
        assert_eq!(spec.scheme, "socks5h");
        assert_eq!(spec.port, 1080);
        assert_eq!(spec.username, None);
    }

    #[test]
    fn normalizes_scheme_case() {
        let spec = parse_proxy_url("HTTPS://proxy.corp.example:8443").unwrap();
        assert_eq!(spec.scheme, "https");
    }

    #[test]
    fn parses_ipv6_bracketed_host() {
        let spec = parse_proxy_url("http://[::1]:7890").unwrap();
        assert_eq!(spec.host, "::1");
        assert_eq!(spec.port, 7890);
    }

    #[test]
    fn rejects_bad_input() {
        assert!(parse_proxy_url("ssh://127.0.0.1:22").is_err());
        assert!(parse_proxy_url("socks5://127.0.0.1").is_err());
        assert!(parse_proxy_url("socks5://127.0.0.1:notaport").is_err());
        assert!(parse_proxy_url("   ").is_err());
    }

    #[test]
    fn parse_connect_status_partial_and_complete() {
        assert_eq!(parse_connect_status(b"HTTP/1.1 200 OK\r\n"), None);
        assert_eq!(
            parse_connect_status(b"HTTP/1.1 200 OK\r\n\r\nextra"),
            Some(200)
        );
        assert_eq!(parse_connect_status(b"garbage\r\n\r\n"), None);
    }

    /// 假 HTTP 代理：校验 CONNECT 行与认证头 → 应答指定状态码 → 回显隧道字节。
    async fn spawn_fake_proxy(status_line: &'static str) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 1024];
            let n = sock.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            assert!(
                req.starts_with("CONNECT rprotocol.rithmic.com:443 HTTP/1.1\r\n"),
                "CONNECT 行不符: {req}"
            );
            assert!(
                req.contains("Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"),
                "缺少/错误认证头: {req}"
            );
            sock.write_all(status_line.as_bytes()).await.unwrap();
            sock.write_all(b"\r\n\r\n").await.unwrap();
            // 隧道建立后回显
            let mut echo = [0u8; 4];
            if sock.read_exact(&mut echo).await.is_ok() {
                let _ = sock.write_all(&echo).await;
            }
        });
        addr
    }

    #[tokio::test]
    async fn http_connect_tunnel_ok_with_auth() {
        let addr = spawn_fake_proxy("HTTP/1.1 200 Connection established").await;
        let spec = parse_proxy_url(&format!("http://user:pass@{addr}")).unwrap();
        let mut tunnel = http_connect_tunnel(&spec, "rprotocol.rithmic.com", 443)
            .await
            .unwrap();
        tunnel.write_all(b"ping").await.unwrap();
        let mut got = [0u8; 4];
        tunnel.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ping");
    }

    #[tokio::test]
    async fn http_connect_tunnel_rejected_status_is_error() {
        let addr = spawn_fake_proxy("HTTP/1.1 407 Proxy Auth Required").await;
        let spec = parse_proxy_url(&format!("http://{addr}")).unwrap();
        let res = http_connect_tunnel(&spec, "rprotocol.rithmic.com", 443).await;
        assert!(res.is_err());
    }
}

#[cfg(not(target_arch = "wasm32"))]
use crate::constants;
use crate::tsm;
use crate::Result;
use anyhow::anyhow;
#[cfg(not(target_arch = "wasm32"))]
use bytes::Bytes;
#[cfg(not(target_arch = "wasm32"))]
use http_body_util::{BodyExt, Full};
#[cfg(not(target_arch = "wasm32"))]
use hyper::header::HeaderValue;
#[cfg(not(target_arch = "wasm32"))]
use hyper::{Method, Request};
#[cfg(not(target_arch = "wasm32"))]
use hyper_timeout::TimeoutConnector;
#[cfg(not(target_arch = "wasm32"))]
use hyper_tls::HttpsConnector;
#[cfg(not(target_arch = "wasm32"))]
use hyper_util::client::legacy::Client;
#[cfg(not(target_arch = "wasm32"))]
use hyper_util::rt::TokioExecutor;
#[cfg(not(target_arch = "wasm32"))]
use std::time::Duration;
#[cfg(not(target_arch = "wasm32"))]
use tokio::runtime::Runtime;

#[cfg(not(target_arch = "wasm32"))]
pub fn post(action: &str, req_data: Vec<u8>) -> Result<String> {
    let f = async_post(action, req_data);
    Runtime::new()?.block_on(f)
}

#[cfg(target_arch = "wasm32")]
pub fn post(_action: &str, _req_data: Vec<u8>) -> Result<String> {
    Err(anyhow!("imkey_tsm_web_adapter_required"))
}

#[cfg(not(target_arch = "wasm32"))]
async fn async_post(action: &str, req_data: Vec<u8>) -> Result<String> {
    let uri = tsm::request_uri(action)?;
    async_post_uri(uri, req_data).await
}

async fn async_post_uri(uri: hyper::Uri, req_data: Vec<u8>) -> Result<String> {
    let mut req = Request::new(Full::new(Bytes::from(req_data)));
    *req.method_mut() = Method::POST;
    *req.uri_mut() = uri.clone();
    req.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );

    let https = HttpsConnector::new();
    let mut connector = TimeoutConnector::new(https);
    connector.set_connect_timeout(Some(Duration::from_secs(
        constants::NETWORK_CONN_TIMEOUT as u64,
    )));
    connector.set_read_timeout(Some(Duration::from_secs(
        constants::NETWORK_READ_TIMEOUT as u64,
    )));
    connector.set_write_timeout(Some(Duration::from_secs(
        constants::NETWORK_WRITE_TIMEOUT as u64,
    )));
    let client = Client::builder(TokioExecutor::new()).build::<_, Full<Bytes>>(connector);

    let resp = client.request(req).await?;
    if !resp.status().is_success() {
        return Err(anyhow!("imkey_tsm_server_error"));
    }

    let bytes = resp.into_body().collect().await?.to_bytes();
    let res_data = std::str::from_utf8(&bytes)?.to_string();
    Ok(res_data)
}

#[cfg(test)]
mod test {
    use crate::constants;
    use crate::https::async_post_uri;
    use crate::tsm::{normalize_test_tsm_url, request_uri_with_base};
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;
    use tokio::runtime::Runtime;

    #[test]
    fn post_test_uses_a_local_server() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            loop {
                let mut chunk = [0u8; 512];
                let read = stream.read(&mut chunk).unwrap();
                assert!(read > 0, "request ended before the HTTP headers");
                request.extend_from_slice(&chunk[..read]);
                assert!(request.len() <= 8_192, "request headers are too large");
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let request = String::from_utf8_lossy(&request);
            assert!(request.starts_with("POST /imkey/seInfoQuery HTTP/1.1"));
            assert!(request.contains("content-type: application/json"));
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 15\r\nConnection: close\r\n\r\n{\"result\":\"ok\"}",
                )
                .unwrap();
        });

        let base_url = normalize_test_tsm_url(&format!("http://{address}/imkey")).unwrap();
        let uri = request_uri_with_base(&base_url, constants::TSM_ACTION_SE_QUERY).unwrap();
        let response = Runtime::new()
            .unwrap()
            .block_on(async_post_uri(uri, b"{}".to_vec()))
            .unwrap();
        server.join().unwrap();
        assert_eq!("{\"result\":\"ok\"}", response);
    }
}

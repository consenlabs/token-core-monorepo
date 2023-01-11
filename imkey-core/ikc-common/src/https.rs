use crate::constants;
use crate::Result;
use hyper::header::HeaderValue;
use hyper::Client;
use hyper::{Body, Method, Request};
use hyper_timeout::TimeoutConnector;
use hyper_tls::HttpsConnector;
use std::time::Duration;
use tokio::runtime::Runtime;

pub fn post(action: &str, req_data: Vec<u8>) -> Result<String> {
    let f = async_post(action, req_data);
    Runtime::new().unwrap().block_on(f)
}

async fn async_post(action: &str, req_data: Vec<u8>) -> Result<String> {
    let uri: hyper::Uri = format!("{}{}", constants::URL.to_string(), action)
        .to_string()
        .parse()
        .unwrap();
    let mut req = Request::new(Body::from(req_data));
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
    let client = Client::builder().build::<_, hyper::Body>(connector);

    let resp = client.request(req).await?;

    let bytes = hyper::body::to_bytes(resp.into_body()).await?;
    let res_data = std::str::from_utf8(&bytes).unwrap().to_string();
    Ok(res_data)
}

#[cfg(test)]
mod test {
    use crate::constants;
    use crate::https::post;
    use hex::FromHex;

    #[test]
    fn post_test() {
        let data = Vec::from_hex("7b0a20202273656964223a20223139303630303030303030323030383630303031303130303030303030303134222c0a202022736e223a2022696d4b65793031313931323030303031222c0a20202273646b56657273696f6e223a206e756c6c2c0a202022737465704b6579223a20223031222c0a202022737461747573576f7264223a206e756c6c2c0a202022636f6d6d616e644944223a20222f7365496e666f5175657279222c0a20202263617264526574446174614c697374223a206e756c6c0a7d").unwrap();
        assert!(post(constants::TSM_ACTION_SE_QUERY, data).is_ok());
    }
}

//! Bound buffered integration responses before retaining a complete backend payload.
//! AWS documents the 10 MB buffered response limit separately from response streaming:
//! https://docs.aws.amazon.com/apigateway/latest/developerguide/response-transfer-mode.html
use bytes::{Bytes, BytesMut};

pub(crate) const MAX_RESPONSE_BYTES: usize = 10 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BodyError {
    Timeout,
    TooLarge,
    Read,
}

fn read_error(error: reqwest::Error) -> BodyError {
    if error.is_timeout() {
        BodyError::Timeout
    } else {
        BodyError::Read
    }
}

pub(crate) async fn read_response(mut response: reqwest::Response) -> Result<Bytes, BodyError> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        return Err(BodyError::TooLarge);
    }
    let mut body = BytesMut::new();
    while let Some(chunk) = response.chunk().await.map_err(read_error)? {
        let length = body
            .len()
            .checked_add(chunk.len())
            .filter(|length| *length <= MAX_RESPONSE_BYTES)
            .ok_or(BodyError::TooLarge)?;
        body.reserve(length - body.len());
        body.extend_from_slice(&chunk);
    }
    Ok(body.freeze())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;
    use tokio::task::JoinHandle;

    async fn backend(
        headers: String,
        body: Vec<u8>,
        gate: Option<oneshot::Receiver<()>>,
        timeout: Duration,
    ) -> (reqwest::Response, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let worker = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                socket.read_exact(&mut byte).await.unwrap();
                request.push(byte[0]);
                assert!(request.len() <= 8192);
            }
            socket.write_all(headers.as_bytes()).await.unwrap();
            if !body.is_empty() {
                // The bounded reader may stop before the entire oversized fixture is written.
                if socket.write_all(&body).await.is_err() {
                    return;
                }
            }
            if let Some(gate) = gate {
                let _ = gate.await;
            }
        });
        let response = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(timeout)
            .build()
            .unwrap()
            .get(format!("http://{address}/owned"))
            .send()
            .await
            .unwrap();
        (response, worker)
    }

    #[tokio::test]
    async fn exact_buffered_limit_is_accepted() {
        let (response, worker) = backend(
            format!("HTTP/1.1 200 OK\r\nContent-Length: {MAX_RESPONSE_BYTES}\r\nConnection: close\r\n\r\n"),
            vec![b'x'; MAX_RESPONSE_BYTES],
            None,
            Duration::from_secs(5),
        )
        .await;
        let body = read_response(response).await.unwrap();
        assert_eq!(body.len(), MAX_RESPONSE_BYTES);
        assert!(body.iter().all(|byte| *byte == b'x'));
        worker.await.unwrap();
    }

    #[tokio::test]
    async fn oversized_content_length_is_rejected_without_waiting_for_body() {
        let (release, gate) = oneshot::channel();
        let (response, worker) = backend(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                MAX_RESPONSE_BYTES + 1
            ),
            Vec::new(),
            Some(gate),
            Duration::from_secs(5),
        )
        .await;
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), read_response(response))
                .await
                .unwrap(),
            Err(BodyError::TooLarge)
        );
        release.send(()).unwrap();
        worker.await.unwrap();
    }

    #[tokio::test]
    async fn oversized_chunked_body_is_rejected_without_content_length() {
        let mut wire = format!("{:x}\r\n", MAX_RESPONSE_BYTES + 1).into_bytes();
        wire.extend(std::iter::repeat_n(b'x', MAX_RESPONSE_BYTES + 1));
        wire.extend_from_slice(b"\r\n0\r\n\r\n");
        let (response, worker) = backend(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".into(),
            wire,
            None,
            Duration::from_secs(5),
        )
        .await;
        assert_eq!(response.content_length(), None);
        assert_eq!(read_response(response).await, Err(BodyError::TooLarge));
        worker.await.unwrap();
    }

    #[tokio::test]
    async fn stalled_body_timeout_is_distinct_from_read_failure() {
        let (release, gate) = oneshot::channel();
        let (response, worker) = backend(
            "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\n".into(),
            Vec::new(),
            Some(gate),
            Duration::from_millis(200),
        )
        .await;
        assert_eq!(read_response(response).await, Err(BodyError::Timeout));
        release.send(()).unwrap();
        worker.await.unwrap();

        let (response, worker) = backend(
            "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\n".into(),
            Vec::new(),
            None,
            Duration::from_secs(5),
        )
        .await;
        assert_eq!(read_response(response).await, Err(BodyError::Read));
        worker.await.unwrap();
    }
}

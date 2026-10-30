// Copyright 2026 Deno Land Inc. Apache-2.0 license.

//! rtpengine media sidecar adapter.
//!
//! Provides an asynchronous client to communicate with an external rtpengine
//! daemon over UDP using the rtpengine NG protocol.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use celld_logic::rtpengine::{
    BencodeValue, RtpEngineCommandBuilder, RtpEngineMessage,
};
use tokio::net::UdpSocket;

static COOKIE_COUNTER: AtomicU64 = AtomicU64::new(1);

fn next_cookie(prefix: &str) -> String {
    let id = COOKIE_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{prefix}_{id}")
}

#[derive(Clone)]
pub struct RtpEngineClient {
    endpoint: SocketAddr,
    socket: Arc<UdpSocket>,
}

impl RtpEngineClient {
    pub async fn bind(endpoint: SocketAddr, bind_addr: SocketAddr) -> Result<Self> {
        let socket = UdpSocket::bind(bind_addr).await.context("failed to bind rtpengine client socket")?;
        Ok(Self {
            endpoint,
            socket: Arc::new(socket),
        })
    }

    pub fn from_socket(endpoint: SocketAddr, socket: Arc<UdpSocket>) -> Self {
        Self { endpoint, socket }
    }

    pub fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }

    /// Sends an NG command to rtpengine and awaits the matching response.
    pub async fn send_command(&self, message: RtpEngineMessage) -> Result<BencodeValue> {
        let cookie = message.cookie.clone();
        let bytes = message.serialize();
        self.socket
            .send_to(&bytes, self.endpoint)
            .await
            .context("failed to send rtpengine packet")?;

        let mut buf = vec![0u8; 65535];
        // Read response
        let (len, _src) = self
            .socket
            .recv_from(&mut buf)
            .await
            .context("failed to receive rtpengine response")?;

        let resp_msg = RtpEngineMessage::parse(&buf[..len])
            .map_err(|e| anyhow!("failed to parse rtpengine response: {e}"))?;

        if resp_msg.cookie != cookie {
            return Err(anyhow!(
                "rtpengine cookie mismatch: expected {cookie}, got {}",
                resp_msg.cookie
            ));
        }

        let result = resp_msg.payload.dict_get_str("result");
        if result == Some("error") {
            let reason = resp_msg
                .payload
                .dict_get_str("error-reason")
                .unwrap_or("unknown error");
            return Err(anyhow!("rtpengine error: {reason}"));
        }

        Ok(resp_msg.payload)
    }

    pub async fn ping(&self) -> Result<()> {
        let cookie = next_cookie("ping");
        let cmd = RtpEngineCommandBuilder::ping(&cookie);
        let resp = self.send_command(cmd).await?;
        if resp.dict_get_str("result") == Some("pong") || resp.dict_get_str("result") == Some("ok") {
            Ok(())
        } else {
            Err(anyhow!("rtpengine ping did not answer pong or ok"))
        }
    }

    pub async fn offer(
        &self,
        call_id: &str,
        from_tag: &str,
        sdp: &str,
        direction: Option<(&str, &str)>,
    ) -> Result<String> {
        let cookie = next_cookie("offer");
        let cmd = RtpEngineCommandBuilder::offer(&cookie, call_id, from_tag, sdp, direction);
        let resp = self.send_command(cmd).await?;
        resp.dict_get_str("sdp")
            .map(str::to_string)
            .ok_or_else(|| anyhow!("rtpengine offer response missing sdp"))
    }

    pub async fn answer(
        &self,
        call_id: &str,
        from_tag: &str,
        to_tag: &str,
        sdp: &str,
        direction: Option<(&str, &str)>,
    ) -> Result<String> {
        let cookie = next_cookie("answer");
        let cmd = RtpEngineCommandBuilder::answer(&cookie, call_id, from_tag, to_tag, sdp, direction);
        let resp = self.send_command(cmd).await?;
        resp.dict_get_str("sdp")
            .map(str::to_string)
            .ok_or_else(|| anyhow!("rtpengine answer response missing sdp"))
    }

    pub async fn delete(
        &self,
        call_id: &str,
        from_tag: Option<&str>,
        to_tag: Option<&str>,
    ) -> Result<()> {
        let cookie = next_cookie("del");
        let cmd = RtpEngineCommandBuilder::delete(&cookie, call_id, from_tag, to_tag);
        let _ = self.send_command(cmd).await?;
        Ok(())
    }
}

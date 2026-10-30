// Copyright 2026 Deno Land Inc. Apache-2.0 license.

//! Pure Session Initiation Protocol (RFC 3261) validation, parser, digest auth,
//! and transaction state machines, sans I/O.

#![allow(clippy::should_implement_trait, clippy::inherent_to_string, clippy::large_enum_variant)]

use std::collections::{BTreeMap, BTreeSet};

/// Supported transport protocols for SIP signaling.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SipProtocol {
    Udp,
    Tcp,
    Tls,
    Ws,
}

impl SipProtocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
            Self::Tls => "tls",
            Self::Ws => "ws",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "udp" | "UDP" => Some(Self::Udp),
            "tcp" | "TCP" => Some(Self::Tcp),
            "tls" | "TLS" => Some(Self::Tls),
            "ws" | "WS" => Some(Self::Ws),
            _ => None,
        }
    }

    pub fn is_reliable(self) -> bool {
        matches!(self, Self::Tcp | Self::Tls | Self::Ws)
    }
}

/// One listener configuration declared in deployment config.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SipListenerConfig {
    pub protocol: SipProtocol,
    pub port: u16,
    pub cert: Option<String>,
    pub key: Option<String>,
    pub path: Option<String>,
}

/// The normalized deployment configuration for SIP support.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SipConfig {
    pub domains: Vec<String>,
    pub listeners: Vec<SipListenerConfig>,
    pub auto_100_trying: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigError {
    pub field: &'static str,
    pub message: &'static str,
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.field, self.message)
    }
}

impl std::error::Error for ConfigError {}

/// Validate SIP deployment bounds and listener configuration.
pub fn validate_config(config: &SipConfig) -> Result<(), ConfigError> {
    let fail = |field, message| ConfigError { field, message };

    if config.domains.is_empty() {
        return Err(fail("domains", "must not be empty"));
    }

    for domain in &config.domains {
        if domain.is_empty() {
            return Err(fail("domains", "domain name must not be empty"));
        }
        if domain.len() > crate::http::MAX_AUTHORITY {
            return Err(fail("domains", "domain name exceeds maximum authority length"));
        }
        if crate::http::authority_decision(domain) == crate::http::AuthorityDecision::Reject {
            return Err(fail("domains", "domain contains invalid syntax or characters"));
        }
    }

    if config.listeners.is_empty() {
        return Err(fail("listeners", "must declare at least one listener"));
    }

    let mut seen = BTreeSet::new();

    for listener in &config.listeners {
        if listener.port == 0 {
            return Err(fail("listeners.port", "port must be greater than 0"));
        }

        let key = (
            listener.protocol,
            listener.port,
            listener.path.as_deref().unwrap_or(""),
        );
        if !seen.insert(key) {
            return Err(fail(
                "listeners",
                "duplicate listener protocol, port, and path combination",
            ));
        }

        match listener.protocol {
            SipProtocol::Tls => {
                if listener.cert.as_deref().unwrap_or("").is_empty() {
                    return Err(fail("listeners.cert", "tls listener requires cert path"));
                }
                if listener.key.as_deref().unwrap_or("").is_empty() {
                    return Err(fail("listeners.key", "tls listener requires key path"));
                }
                if listener.path.is_some() {
                    return Err(fail("listeners.path", "path is only supported for ws listener"));
                }
            }
            SipProtocol::Ws => {
                if let Some(path) = &listener.path {
                    if !path.starts_with('/') {
                        return Err(fail("listeners.path", "websocket path must start with '/'"));
                    }
                }
                if listener.cert.is_some() || listener.key.is_some() {
                    return Err(fail(
                        "listeners",
                        "cert and key are only supported for tls listener",
                    ));
                }
            }
            SipProtocol::Udp | SipProtocol::Tcp => {
                if listener.cert.is_some() || listener.key.is_some() {
                    return Err(fail(
                        "listeners",
                        "cert and key are only supported for tls listener",
                    ));
                }
                if listener.path.is_some() {
                    return Err(fail("listeners.path", "path is only supported for ws listener"));
                }
            }
        }
    }

    Ok(())
}

// ============================================================================
// RFC 3261 Wire Types & Parser / Serializer
// ============================================================================

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SipUri {
    pub scheme: String, // "sip" or "sips"
    pub user: Option<String>,
    pub password: Option<String>,
    pub host: String,
    pub port: Option<u16>,
    pub params: BTreeMap<String, Option<String>>,
    pub headers: BTreeMap<String, String>,
}

impl SipUri {
    pub fn user_at_host(&self) -> String {
        match &self.user {
            Some(u) => format!("{u}@{}", self.host),
            None => self.host.clone(),
        }
    }

    pub fn to_string(&self) -> String {
        let mut s = format!("{}:", self.scheme);
        if let Some(user) = &self.user {
            s.push_str(user);
            if let Some(pw) = &self.password {
                s.push(':');
                s.push_str(pw);
            }
            s.push('@');
        }
        s.push_str(&self.host);
        if let Some(port) = self.port {
            s.push_str(&format!(":{port}"));
        }
        for (k, v) in &self.params {
            s.push(';');
            s.push_str(k);
            if let Some(val) = v {
                s.push('=');
                s.push_str(val);
            }
        }
        if !self.headers.is_empty() {
            s.push('?');
            let mut first = true;
            for (k, v) in &self.headers {
                if !first {
                    s.push('&');
                }
                first = false;
                s.push_str(&format!("{k}={v}"));
            }
        }
        s
    }

    pub fn parse(input: &str) -> Result<Self, ParseError> {
        let (scheme, rest) = input
            .split_once(':')
            .ok_or(ParseError::InvalidUri("missing scheme colon"))?;
        let scheme = scheme.to_ascii_lowercase();
        if scheme != "sip" && scheme != "sips" {
            return Err(ParseError::InvalidUri("scheme must be sip or sips"));
        }

        // Split off headers ('?')
        let (main_part, header_part) = match rest.split_once('?') {
            Some((m, h)) => (m, Some(h)),
            None => (rest, None),
        };

        // Split off params (';')
        let mut param_splits = main_part.split(';');
        let user_host_port = param_splits.next().unwrap_or("");

        let mut params = BTreeMap::new();
        for p in param_splits {
            if p.is_empty() {
                continue;
            }
            match p.split_once('=') {
                Some((k, v)) => {
                    params.insert(k.to_ascii_lowercase(), Some(v.to_string()));
                }
                None => {
                    params.insert(p.to_ascii_lowercase(), None);
                }
            }
        }

        let (user_pass, host_port) = match user_host_port.split_once('@') {
            Some((up, hp)) => (Some(up), hp),
            None => (None, user_host_port),
        };

        let (user, password) = match user_pass {
            Some(up) => match up.split_once(':') {
                Some((u, p)) => (Some(u.to_string()), Some(p.to_string())),
                None => (Some(up.to_string()), None),
            },
            None => (None, None),
        };

        let (host, port) = parse_host_port(host_port)?;

        let mut headers = BTreeMap::new();
        if let Some(h) = header_part {
            for kv in h.split('&') {
                if let Some((k, v)) = kv.split_once('=') {
                    headers.insert(k.to_string(), v.to_string());
                }
            }
        }

        Ok(SipUri {
            scheme,
            user,
            password,
            host,
            port,
            params,
            headers,
        })
    }
}

fn parse_host_port(input: &str) -> Result<(String, Option<u16>), ParseError> {
    if input.is_empty() {
        return Err(ParseError::InvalidUri("empty host"));
    }
    if let Some(rest) = input.strip_prefix('[') {
        let (ipv6, tail) = rest
            .split_once(']')
            .ok_or(ParseError::InvalidUri("unmatched IPv6 bracket"))?;
        let port = match tail.strip_prefix(':') {
            Some(p) => Some(
                p.parse::<u16>()
                    .map_err(|_| ParseError::InvalidUri("invalid port"))?,
            ),
            None => None,
        };
        Ok((format!("[{ipv6}]"), port))
    } else {
        match input.split_once(':') {
            Some((h, p)) => {
                let port = p
                    .parse::<u16>()
                    .map_err(|_| ParseError::InvalidUri("invalid port"))?;
                Ok((h.to_string(), Some(port)))
            }
            None => Ok((input.to_string(), None)),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SipVia {
    pub version: String, // typically "SIP/2.0"
    pub transport: SipProtocol,
    pub sent_by: String, // "host:port" or "host"
    pub branch: Option<String>,
    pub received: Option<String>,
    pub rport: Option<u16>,
    pub params: BTreeMap<String, Option<String>>,
}

impl SipVia {
    pub fn parse(s: &str) -> Result<Self, ParseError> {
        let mut parts = s.split(';');
        let first = parts.next().ok_or(ParseError::InvalidVia("empty via"))?.trim();
        let (proto_part, sent_by) = first
            .split_once(char::is_whitespace)
            .ok_or(ParseError::InvalidVia("missing protocol or sent-by"))?;
        let sent_by = sent_by.trim().to_string();

        let mut proto_pieces = proto_part.split('/');
        let name = proto_pieces.next().unwrap_or("").trim();
        let version = proto_pieces.next().unwrap_or("").trim();
        let trans = proto_pieces.next().unwrap_or("").trim();
        if !name.eq_ignore_ascii_case("SIP") || version != "2.0" {
            return Err(ParseError::InvalidVia("protocol must be SIP/2.0"));
        }
        let transport = SipProtocol::from_str(trans)
            .ok_or(ParseError::InvalidVia("unknown transport in via"))?;

        let mut branch = None;
        let mut received = None;
        let mut rport = None;
        let mut params = BTreeMap::new();

        for p in parts {
            let p = p.trim();
            if p.is_empty() {
                continue;
            }
            match p.split_once('=') {
                Some((k, v)) => {
                    let k_lower = k.trim().to_ascii_lowercase();
                    let val = v.trim().to_string();
                    if k_lower == "branch" {
                        branch = Some(val.clone());
                    } else if k_lower == "received" {
                        received = Some(val.clone());
                    } else if k_lower == "rport" {
                        rport = val.parse::<u16>().ok();
                    }
                    params.insert(k_lower, Some(val));
                }
                None => {
                    let k_lower = p.to_ascii_lowercase();
                    if k_lower == "rport" {
                        rport = None; // present without value (RFC 3581 client flag)
                    }
                    params.insert(k_lower, None);
                }
            }
        }

        Ok(SipVia {
            version: "SIP/2.0".to_string(),
            transport,
            sent_by,
            branch,
            received,
            rport,
            params,
        })
    }

    pub fn to_string(&self) -> String {
        let mut s = format!(
            "{}/{} {}",
            self.version,
            self.transport.as_str().to_ascii_uppercase(),
            self.sent_by
        );
        if let Some(b) = &self.branch {
            s.push_str(&format!(";branch={b}"));
        }
        if let Some(r) = &self.received {
            s.push_str(&format!(";received={r}"));
        }
        if let Some(rp) = self.rport {
            s.push_str(&format!(";rport={rp}"));
        } else if self.params.contains_key("rport") {
            s.push_str(";rport");
        }
        for (k, v) in &self.params {
            if k == "branch" || k == "received" || k == "rport" {
                continue;
            }
            s.push(';');
            s.push_str(k);
            if let Some(val) = v {
                s.push('=');
                s.push_str(val);
            }
        }
        s
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SipNameAddr {
    pub display_name: Option<String>,
    pub uri: SipUri,
    pub tag: Option<String>,
    pub params: BTreeMap<String, Option<String>>,
}

impl SipNameAddr {
    pub fn parse(s: &str) -> Result<Self, ParseError> {
        let s = s.trim();
        let (display_name, uri_str, param_str) = if let Some(open) = s.find('<') {
            let close = s[open..]
                .find('>')
                .ok_or(ParseError::InvalidHeader("unclosed angle bracket in URI"))?
                + open;
            let display = s[..open].trim();
            let display_name = if display.is_empty() {
                None
            } else {
                Some(display.trim_matches('"').to_string())
            };
            let uri_str = &s[open + 1..close];
            let param_str = &s[close + 1..];
            (display_name, uri_str, param_str)
        } else {
            match s.split_once(';') {
                Some((u, p)) => (None, u.trim(), p),
                None => (None, s.trim(), ""),
            }
        };

        let uri = SipUri::parse(uri_str)?;
        let mut tag = None;
        let mut params = BTreeMap::new();

        for p in param_str.split(';') {
            let p = p.trim();
            if p.is_empty() {
                continue;
            }
            match p.split_once('=') {
                Some((k, v)) => {
                    let k_lower = k.trim().to_ascii_lowercase();
                    let val = v.trim().to_string();
                    if k_lower == "tag" {
                        tag = Some(val.clone());
                    }
                    params.insert(k_lower, Some(val));
                }
                None => {
                    params.insert(p.to_ascii_lowercase(), None);
                }
            }
        }

        Ok(SipNameAddr {
            display_name,
            uri,
            tag,
            params,
        })
    }

    pub fn to_string(&self) -> String {
        let mut s = String::new();
        if let Some(name) = &self.display_name {
            s.push_str(&format!("\"{name}\" <{}>", self.uri.to_string()));
        } else {
            s.push_str(&format!("<{}>", self.uri.to_string()));
        }
        if let Some(t) = &self.tag {
            s.push_str(&format!(";tag={t}"));
        }
        for (k, v) in &self.params {
            if k == "tag" {
                continue;
            }
            s.push(';');
            s.push_str(k);
            if let Some(val) = v {
                s.push('=');
                s.push_str(val);
            }
        }
        s
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SipContact {
    pub name_addr: SipNameAddr,
    pub expires: Option<u32>,
    pub q: Option<String>,
    pub params: BTreeMap<String, Option<String>>,
}

impl SipContact {
    pub fn parse(s: &str) -> Result<Self, ParseError> {
        let name_addr = SipNameAddr::parse(s)?;
        let mut expires = None;
        let mut q = None;
        let mut params = BTreeMap::new();

        for (k, v) in &name_addr.params {
            if k == "expires" {
                if let Some(val) = v {
                    expires = val.parse::<u32>().ok();
                }
            } else if k == "q" {
                q = v.clone();
            } else {
                params.insert(k.clone(), v.clone());
            }
        }

        Ok(SipContact {
            name_addr,
            expires,
            q,
            params,
        })
    }

    pub fn to_string(&self) -> String {
        let mut s = self.name_addr.to_string();
        if let Some(exp) = self.expires {
            s.push_str(&format!(";expires={exp}"));
        }
        if let Some(q_val) = &self.q {
            s.push_str(&format!(";q={q_val}"));
        }
        s
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SipTransportMeta {
    pub protocol: SipProtocol,
    pub source_address: String,
    pub destination_address: Option<String>,
    pub node_id: String,
    pub listener_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SipRequestData {
    pub method: String,
    pub uri: SipUri,
    pub version: String,
    pub vias: Vec<SipVia>,
    pub from: SipNameAddr,
    pub to: SipNameAddr,
    pub call_id: String,
    pub cseq: (u32, String),
    pub contacts: Vec<SipContact>,
    pub max_forwards: u8,
    pub expires: Option<u32>,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub transport: SipTransportMeta,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SipResponseData {
    pub status: u16,
    pub reason: String,
    pub version: String,
    pub vias: Vec<SipVia>,
    pub from: SipNameAddr,
    pub to: SipNameAddr,
    pub call_id: String,
    pub cseq: (u32, String),
    pub contacts: Vec<SipContact>,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SipMessage {
    Request(SipRequestData),
    Response(SipResponseData),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParseError {
    IncompleteMessage,
    InvalidStartLine,
    InvalidHeader(&'static str),
    InvalidUri(&'static str),
    InvalidVia(&'static str),
    MissingHeader(&'static str),
    ContentLengthMismatch,
    MessageTooLarge,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IncompleteMessage => write!(f, "SIP message incomplete"),
            Self::InvalidStartLine => write!(f, "invalid SIP start line"),
            Self::InvalidHeader(msg) => write!(f, "invalid SIP header: {msg}"),
            Self::InvalidUri(msg) => write!(f, "invalid SIP URI: {msg}"),
            Self::InvalidVia(msg) => write!(f, "invalid SIP Via: {msg}"),
            Self::MissingHeader(h) => write!(f, "missing required SIP header: {h}"),
            Self::ContentLengthMismatch => write!(f, "body length does not match Content-Length"),
            Self::MessageTooLarge => write!(f, "SIP message exceeds maximum size (64KB)"),
        }
    }
}

impl std::error::Error for ParseError {}

pub const MAX_SIP_MESSAGE_BYTES: usize = 65536;

/// Canonicalize SIP header names (including compact form expansion per RFC 3261 §7.3.3).
pub fn canonicalize_header_name(name: &str) -> String {
    let lower = name.trim().to_ascii_lowercase();
    match lower.as_str() {
        "v" | "via" => "via".to_string(),
        "f" | "from" => "from".to_string(),
        "t" | "to" => "to".to_string(),
        "i" | "call-id" => "call-id".to_string(),
        "c" | "content-type" => "content-type".to_string(),
        "l" | "content-length" => "content-length".to_string(),
        "m" | "contact" => "contact".to_string(),
        "s" | "subject" => "subject".to_string(),
        "k" | "supported" => "supported".to_string(),
        _ => lower,
    }
}

/// Parse raw SIP wire bytes into a `SipMessage` and return the total consumed byte count.
pub fn parse_sip_message(
    bytes: &[u8],
    transport: SipTransportMeta,
) -> Result<Option<(SipMessage, usize)>, ParseError> {
    if bytes.len() > MAX_SIP_MESSAGE_BYTES {
        return Err(ParseError::MessageTooLarge);
    }

    // Find CRLF CRLF header-body boundary
    let header_end = match bytes.windows(4).position(|w| w == b"\r\n\r\n") {
        Some(pos) => pos,
        None => return Ok(None), // header section incomplete
    };

    let header_bytes = &bytes[..header_end];
    let header_str = std::str::from_utf8(header_bytes)
        .map_err(|_| ParseError::InvalidHeader("headers are not valid UTF-8"))?;

    // Unfold multi-line headers (RFC 3261 §7.3.1)
    let mut lines: Vec<String> = Vec::new();
    for raw_line in header_str.split("\r\n") {
        if raw_line.starts_with(' ') || raw_line.starts_with('\t') {
            if let Some(prev) = lines.last_mut() {
                prev.push(' ');
                prev.push_str(raw_line.trim());
                continue;
            }
        }
        lines.push(raw_line.to_string());
    }

    if lines.is_empty() {
        return Err(ParseError::InvalidStartLine);
    }

    let start_line = lines[0].trim();
    let is_response = start_line.starts_with("SIP/2.0 ");

    let mut raw_headers: Vec<(String, String)> = Vec::new();
    let mut vias = Vec::new();
    let mut from: Option<SipNameAddr> = None;
    let mut to: Option<SipNameAddr> = None;
    let mut call_id: Option<String> = None;
    let mut cseq: Option<(u32, String)> = None;
    let mut contacts = Vec::new();
    let mut max_forwards = 70_u8;
    let mut expires: Option<u32> = None;
    let mut content_length: Option<usize> = None;

    for line in &lines[1..] {
        if line.is_empty() {
            continue;
        }
        let (name, val) = line
            .split_once(':')
            .ok_or(ParseError::InvalidHeader("missing header colon"))?;
        let name_canon = canonicalize_header_name(name);
        let val_trim = val.trim();

        match name_canon.as_str() {
            "via" => {
                // A single Via line can contain comma-separated entries
                for item in val_trim.split(',') {
                    if !item.trim().is_empty() {
                        vias.push(SipVia::parse(item)?);
                    }
                }
            }
            "from" => {
                from = Some(SipNameAddr::parse(val_trim)?);
            }
            "to" => {
                to = Some(SipNameAddr::parse(val_trim)?);
            }
            "call-id" => {
                call_id = Some(val_trim.to_string());
            }
            "cseq" => {
                let (num_str, meth_str) = val_trim
                    .split_once(char::is_whitespace)
                    .ok_or(ParseError::InvalidHeader("invalid CSeq format"))?;
                let seq_num = num_str
                    .parse::<u32>()
                    .map_err(|_| ParseError::InvalidHeader("invalid CSeq number"))?;
                cseq = Some((seq_num, meth_str.trim().to_string()));
            }
            "contact" => {
                for item in val_trim.split(',') {
                    if !item.trim().is_empty() {
                        contacts.push(SipContact::parse(item)?);
                    }
                }
            }
            "max-forwards" => {
                max_forwards = val_trim.parse::<u8>().unwrap_or(70);
            }
            "expires" => {
                expires = val_trim.parse::<u32>().ok();
            }
            "content-length" => {
                let len = val_trim
                    .parse::<usize>()
                    .map_err(|_| ParseError::InvalidHeader("invalid Content-Length"))?;
                content_length = Some(len);
            }
            _ => {
                raw_headers.push((name.trim().to_string(), val_trim.to_string()));
            }
        }
    }

    let clen = content_length.unwrap_or(0);
    let total_message_len = header_end + 4 + clen;
    if bytes.len() < total_message_len {
        return Ok(None); // Body not fully received yet
    }

    let body = bytes[header_end + 4..total_message_len].to_vec();

    let from = from.ok_or(ParseError::MissingHeader("From"))?;
    let to = to.ok_or(ParseError::MissingHeader("To"))?;
    let call_id = call_id.ok_or(ParseError::MissingHeader("Call-ID"))?;
    let cseq = cseq.ok_or(ParseError::MissingHeader("CSeq"))?;

    if is_response {
        // SIP/2.0 <status> <reason>
        let mut parts = start_line.splitn(3, ' ');
        let _proto = parts.next().unwrap_or("");
        let status_str = parts.next().ok_or(ParseError::InvalidStartLine)?;
        let status = status_str
            .parse::<u16>()
            .map_err(|_| ParseError::InvalidStartLine)?;
        let reason = parts.next().unwrap_or("").to_string();

        let resp = SipResponseData {
            status,
            reason,
            version: "SIP/2.0".to_string(),
            vias,
            from,
            to,
            call_id,
            cseq,
            contacts,
            headers: raw_headers,
            body,
        };
        Ok(Some((SipMessage::Response(resp), total_message_len)))
    } else {
        // <method> <uri> SIP/2.0
        let mut parts = start_line.split_whitespace();
        let method = parts.next().ok_or(ParseError::InvalidStartLine)?.to_string();
        let uri_str = parts.next().ok_or(ParseError::InvalidStartLine)?;
        let version = parts.next().unwrap_or("SIP/2.0").to_string();
        let uri = SipUri::parse(uri_str)?;

        let req = SipRequestData {
            method,
            uri,
            version,
            vias,
            from,
            to,
            call_id,
            cseq,
            contacts,
            max_forwards,
            expires,
            headers: raw_headers,
            body,
            transport,
        };
        Ok(Some((SipMessage::Request(req), total_message_len)))
    }
}

impl SipRequestData {
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = format!(
            "{} {} {}\r\n",
            self.method,
            self.uri.to_string(),
            self.version
        );
        for via in &self.vias {
            out.push_str(&format!("Via: {}\r\n", via.to_string()));
        }
        out.push_str(&format!("From: {}\r\n", self.from.to_string()));
        out.push_str(&format!("To: {}\r\n", self.to.to_string()));
        out.push_str(&format!("Call-ID: {}\r\n", self.call_id));
        out.push_str(&format!("CSeq: {} {}\r\n", self.cseq.0, self.cseq.1));
        for contact in &self.contacts {
            out.push_str(&format!("Contact: {}\r\n", contact.to_string()));
        }
        out.push_str(&format!("Max-Forwards: {}\r\n", self.max_forwards));
        if let Some(exp) = self.expires {
            out.push_str(&format!("Expires: {exp}\r\n"));
        }
        for (k, v) in &self.headers {
            out.push_str(&format!("{k}: {v}\r\n"));
        }
        out.push_str(&format!("Content-Length: {}\r\n", self.body.len()));
        out.push_str("\r\n");
        let mut bytes = out.into_bytes();
        bytes.extend_from_slice(&self.body);
        bytes
    }
}

impl SipResponseData {
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = format!("{} {} {}\r\n", self.version, self.status, self.reason);
        for via in &self.vias {
            out.push_str(&format!("Via: {}\r\n", via.to_string()));
        }
        out.push_str(&format!("From: {}\r\n", self.from.to_string()));
        out.push_str(&format!("To: {}\r\n", self.to.to_string()));
        out.push_str(&format!("Call-ID: {}\r\n", self.call_id));
        out.push_str(&format!("CSeq: {} {}\r\n", self.cseq.0, self.cseq.1));
        for contact in &self.contacts {
            out.push_str(&format!("Contact: {}\r\n", contact.to_string()));
        }
        for (k, v) in &self.headers {
            out.push_str(&format!("{k}: {v}\r\n"));
        }
        out.push_str(&format!("Content-Length: {}\r\n", self.body.len()));
        out.push_str("\r\n");
        let mut bytes = out.into_bytes();
        bytes.extend_from_slice(&self.body);
        bytes
    }
}

impl SipMessage {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Request(req) => req.serialize(),
            Self::Response(resp) => resp.serialize(),
        }
    }
}

// ============================================================================
// Digest Authentication (RFC 2617 & RFC 8760)
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DigestAlgorithm {
    Md5,
    Sha256,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DigestCredentials {
    pub username: String,
    pub realm: String,
    pub nonce: String,
    pub uri: String,
    pub response: String,
    pub algorithm: DigestAlgorithm,
    pub cnonce: Option<String>,
    pub nc: Option<String>,
    pub qop: Option<String>,
    pub opaque: Option<String>,
}

impl DigestCredentials {
    pub fn parse(header_value: &str) -> Option<Self> {
        let rest = header_value.trim().strip_prefix("Digest ")?;
        let mut pairs = BTreeMap::new();

        for item in rest.split(',') {
            if let Some((k, v)) = item.trim().split_once('=') {
                let k_clean = k.trim().to_ascii_lowercase();
                let v_clean = v.trim().trim_matches('"').to_string();
                pairs.insert(k_clean, v_clean);
            }
        }

        let username = pairs.remove("username")?;
        let realm = pairs.remove("realm")?;
        let nonce = pairs.remove("nonce")?;
        let uri = pairs.remove("uri")?;
        let response = pairs.remove("response")?;
        let algo_str = pairs.get("algorithm").map(|s| s.as_str()).unwrap_or("MD5");
        let algorithm = if algo_str.eq_ignore_ascii_case("SHA-256") {
            DigestAlgorithm::Sha256
        } else {
            DigestAlgorithm::Md5
        };

        Some(DigestCredentials {
            username,
            realm,
            nonce,
            uri,
            response,
            algorithm,
            cnonce: pairs.remove("cnonce"),
            nc: pairs.remove("nc"),
            qop: pairs.remove("qop"),
            opaque: pairs.remove("opaque"),
        })
    }
}

/// Abstract hashing capability injected by adapter host.
pub trait DigestHasher {
    fn hash_md5_hex(&self, data: &[u8]) -> String;
    fn hash_sha256_hex(&self, data: &[u8]) -> String;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DigestVerdict {
    Verified,
    InvalidResponse,
    StaleNonce,
    MissingAuth,
}

pub fn verify_digest(
    creds: &DigestCredentials,
    method: &str,
    ha1_hex: &str,
    hasher: &dyn DigestHasher,
) -> DigestVerdict {
    // HA2 = H(method:digestURI)
    let ha2_input = format!("{}:{}", method, creds.uri);
    let ha2_hex = match creds.algorithm {
        DigestAlgorithm::Md5 => hasher.hash_md5_hex(ha2_input.as_bytes()),
        DigestAlgorithm::Sha256 => hasher.hash_sha256_hex(ha2_input.as_bytes()),
    };

    // Expected Response
    let expected = if let Some(qop) = &creds.qop {
        let qop_lower = qop.to_ascii_lowercase();
        if qop_lower == "auth" || qop_lower == "auth-int" {
            let nc = creds.nc.as_deref().unwrap_or("00000001");
            let cnonce = creds.cnonce.as_deref().unwrap_or("");
            let resp_input = format!(
                "{}:{}:{}:{}:{}:{}",
                ha1_hex, creds.nonce, nc, cnonce, qop_lower, ha2_hex
            );
            match creds.algorithm {
                DigestAlgorithm::Md5 => hasher.hash_md5_hex(resp_input.as_bytes()),
                DigestAlgorithm::Sha256 => hasher.hash_sha256_hex(resp_input.as_bytes()),
            }
        } else {
            return DigestVerdict::InvalidResponse;
        }
    } else {
        let resp_input = format!("{}:{}:{}", ha1_hex, creds.nonce, ha2_hex);
        match creds.algorithm {
            DigestAlgorithm::Md5 => hasher.hash_md5_hex(resp_input.as_bytes()),
            DigestAlgorithm::Sha256 => hasher.hash_sha256_hex(resp_input.as_bytes()),
        }
    };

    if creds.response.eq_ignore_ascii_case(&expected) {
        DigestVerdict::Verified
    } else {
        DigestVerdict::InvalidResponse
    }
}

pub fn format_digest_challenge(realm: &str, nonce: &str, algorithm: DigestAlgorithm, stale: bool) -> String {
    let algo_str = match algorithm {
        DigestAlgorithm::Md5 => "MD5",
        DigestAlgorithm::Sha256 => "SHA-256",
    };
    format!(
        "Digest realm=\"{realm}\", nonce=\"{nonce}\", algorithm={algo_str}, qop=\"auth\", stale={stale}"
    )
}

// ============================================================================
// RFC 3261 Section 17 Transaction State Machine
// ============================================================================

pub const T1_MS: u64 = 500;
pub const T2_MS: u64 = 4000;
pub const T4_MS: u64 = 5000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SipTimerKind {
    TimerA, // INVITE client retransmission
    TimerB, // INVITE client transaction timeout
    TimerD, // INVITE client wait for response retransmits
    TimerE, // Non-INVITE client retransmission
    TimerF, // Non-INVITE client transaction timeout
    TimerG, // INVITE server 3xx-6xx retransmission
    TimerH, // INVITE server wait for ACK
    TimerI, // INVITE server wait for ACK retransmits
    TimerJ, // Non-INVITE server wait for request retransmits
    TimerK, // Non-INVITE client wait for response retransmits
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum SipAction {
    SendWire {
        target_addr: String,
        protocol: SipProtocol,
        bytes: Vec<u8>,
    },
    DeliverRequestToWorker {
        tx_id: u64,
        request: SipRequestData,
    },
    DeliverResponseToClient {
        tx_id: u64,
        response: SipResponseData,
    },
    TransactionTerminated {
        tx_id: u64,
    },
    ArmTimer {
        tx_id: u64,
        timer: SipTimerKind,
        at_mono_ms: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ServerTxState {
    Proceeding {
        is_invite: bool,
        last_provisional: Option<SipResponseData>,
    },
    Completed {
        final_response: SipResponseData,
        is_invite: bool,
    },
    Confirmed,
    Terminated,
}

#[derive(Clone, Debug)]
struct ServerTx {
    _id: u64,
    branch: String,
    method: String,
    transport: SipProtocol,
    source_addr: String,
    state: ServerTxState,
    retransmit_interval_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ClientTxState {
    Calling {
        request: SipRequestData,
    },
    Trying {
        request: SipRequestData,
    },
    Proceeding {
        is_invite: bool,
    },
    Completed {
        is_invite: bool,
    },
    Terminated,
}

#[derive(Clone, Debug)]
struct ClientTx {
    _id: u64,
    branch: String,
    method: String,
    transport: SipProtocol,
    target_addr: String,
    state: ClientTxState,
    retransmit_interval_ms: u64,
}

#[derive(Default)]
pub struct SipTransactionTable {
    next_tx_id: u64,
    server_txs: BTreeMap<u64, ServerTx>,
    client_txs: BTreeMap<u64, ClientTx>,
    server_keys: BTreeMap<(String, String), u64>, // (branch, method) -> tx_id
    client_keys: BTreeMap<(String, String), u64>, // (branch, method) -> tx_id
}

impl SipTransactionTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Process an incoming SIP packet off the wire.
    pub fn handle_incoming(
        &mut self,
        msg: SipMessage,
        now_mono_ms: u64,
        auto_100_trying: bool,
    ) -> Vec<SipAction> {
        match msg {
            SipMessage::Request(req) => self.handle_incoming_request(req, now_mono_ms, auto_100_trying),
            SipMessage::Response(resp) => self.handle_incoming_response(resp, now_mono_ms),
        }
    }

    fn handle_incoming_request(
        &mut self,
        req: SipRequestData,
        now_mono_ms: u64,
        auto_100_trying: bool,
    ) -> Vec<SipAction> {
        let mut actions = Vec::new();
        let top_via = match req.vias.first() {
            Some(v) => v,
            None => return actions, // Dropped: invalid RFC 3261 request missing Via
        };

        let branch = match &top_via.branch {
            Some(b) if b.starts_with("z9hG4bK") => b.clone(),
            _ => return actions, // Non-RFC 3261 compliant branch
        };

        let method = req.method.clone();
        let is_invite = method == "INVITE";
        let is_ack = method == "ACK";

        let lookup_method = if is_ack { "INVITE" } else { &method };
        let key = (branch.clone(), lookup_method.to_string());

        if let Some(&tx_id) = self.server_keys.get(&key) {
            let tx = match self.server_txs.get_mut(&tx_id) {
                Some(t) => t,
                None => return actions,
            };

            match &mut tx.state {
                ServerTxState::Proceeding {
                    last_provisional, ..
                } => {
                    if !is_ack {
                        // Retransmission absorption: send back last provisional response
                        if let Some(prov) = last_provisional {
                            actions.push(SipAction::SendWire {
                                target_addr: tx.source_addr.clone(),
                                protocol: tx.transport,
                                bytes: prov.serialize(),
                            });
                        }
                    }
                }
                ServerTxState::Completed {
                    final_response,
                    is_invite: true,
                } => {
                    if is_ack {
                        // ACK received for INVITE 3xx-6xx: transition to Confirmed
                        tx.state = ServerTxState::Confirmed;
                        if !tx.transport.is_reliable() {
                            actions.push(SipAction::ArmTimer {
                                tx_id,
                                timer: SipTimerKind::TimerI,
                                at_mono_ms: now_mono_ms + T4_MS,
                            });
                        } else {
                            tx.state = ServerTxState::Terminated;
                            actions.push(SipAction::TransactionTerminated { tx_id });
                        }
                    } else {
                        // Retransmit final response
                        actions.push(SipAction::SendWire {
                            target_addr: tx.source_addr.clone(),
                            protocol: tx.transport,
                            bytes: final_response.serialize(),
                        });
                    }
                }
                ServerTxState::Completed {
                    final_response,
                    is_invite: false,
                } => {
                    if !is_ack {
                        // Retransmit non-INVITE final response
                        actions.push(SipAction::SendWire {
                            target_addr: tx.source_addr.clone(),
                            protocol: tx.transport,
                            bytes: final_response.serialize(),
                        });
                    }
                }
                ServerTxState::Confirmed => {
                    // Retransmitted ACK absorbed silently
                }
                ServerTxState::Terminated => {}
            }
            return actions;
        }

        if is_ack {
            // ACK for 2xx or stale transaction is passed directly to TU or absorbed
            return actions;
        }

        // Create new Server Transaction
        self.next_tx_id += 1;
        let tx_id = self.next_tx_id;

        let mut last_provisional = None;
        if is_invite && auto_100_trying {
            // Auto emit 100 Trying
            let trying = SipResponseData {
                status: 100,
                reason: "Trying".to_string(),
                version: "SIP/2.0".to_string(),
                vias: req.vias.clone(),
                from: req.from.clone(),
                to: req.to.clone(),
                call_id: req.call_id.clone(),
                cseq: req.cseq.clone(),
                contacts: Vec::new(),
                headers: Vec::new(),
                body: Vec::new(),
            };
            actions.push(SipAction::SendWire {
                target_addr: req.transport.source_address.clone(),
                protocol: req.transport.protocol,
                bytes: trying.serialize(),
            });
            last_provisional = Some(trying);
        }

        let state = ServerTxState::Proceeding {
            is_invite,
            last_provisional,
        };

        let server_tx = ServerTx {
            _id: tx_id,
            branch: branch.clone(),
            method: method.clone(),
            transport: req.transport.protocol,
            source_addr: req.transport.source_address.clone(),
            state,
            retransmit_interval_ms: T1_MS,
        };

        self.server_txs.insert(tx_id, server_tx);
        self.server_keys.insert((branch, method), tx_id);

        actions.push(SipAction::DeliverRequestToWorker {
            tx_id,
            request: req,
        });

        actions
    }

    /// Deliver a response produced by the Worker / DO cell for a server transaction.
    pub fn handle_worker_response(
        &mut self,
        tx_id: u64,
        resp: SipResponseData,
        now_mono_ms: u64,
    ) -> Vec<SipAction> {
        let mut actions = Vec::new();
        let tx = match self.server_txs.get_mut(&tx_id) {
            Some(t) => t,
            None => return actions,
        };

        let is_invite = tx.method == "INVITE";
        let status = resp.status;

        if status < 200 {
            // Provisional response
            if let ServerTxState::Proceeding {
                last_provisional, ..
            } = &mut tx.state
            {
                *last_provisional = Some(resp.clone());
            }
            actions.push(SipAction::SendWire {
                target_addr: tx.source_addr.clone(),
                protocol: tx.transport,
                bytes: resp.serialize(),
            });
        } else if is_invite {
            if (200..300).contains(&status) {
                // 2xx for INVITE: sent directly to transport, TU handles ACK/retransmission
                tx.state = ServerTxState::Terminated;
                actions.push(SipAction::SendWire {
                    target_addr: tx.source_addr.clone(),
                    protocol: tx.transport,
                    bytes: resp.serialize(),
                });
                actions.push(SipAction::TransactionTerminated { tx_id });
            } else {
                // 300-699 for INVITE
                tx.state = ServerTxState::Completed {
                    final_response: resp.clone(),
                    is_invite: true,
                };
                actions.push(SipAction::SendWire {
                    target_addr: tx.source_addr.clone(),
                    protocol: tx.transport,
                    bytes: resp.serialize(),
                });
                if !tx.transport.is_reliable() {
                    actions.push(SipAction::ArmTimer {
                        tx_id,
                        timer: SipTimerKind::TimerG,
                        at_mono_ms: now_mono_ms + T1_MS,
                    });
                }
                actions.push(SipAction::ArmTimer {
                    tx_id,
                    timer: SipTimerKind::TimerH,
                    at_mono_ms: now_mono_ms + 64 * T1_MS,
                });
            }
        } else {
            // Non-INVITE final response
            tx.state = ServerTxState::Completed {
                final_response: resp.clone(),
                is_invite: false,
            };
            actions.push(SipAction::SendWire {
                target_addr: tx.source_addr.clone(),
                protocol: tx.transport,
                bytes: resp.serialize(),
            });
            if !tx.transport.is_reliable() {
                actions.push(SipAction::ArmTimer {
                    tx_id,
                    timer: SipTimerKind::TimerJ,
                    at_mono_ms: now_mono_ms + 64 * T1_MS,
                });
            } else {
                tx.state = ServerTxState::Terminated;
                actions.push(SipAction::TransactionTerminated { tx_id });
            }
        }

        actions
    }

    /// Start an outbound client transaction (for forking INVITEs or sending BYE/CANCEL).
    pub fn start_client_transaction(
        &mut self,
        req: SipRequestData,
        target_addr: String,
        now_mono_ms: u64,
    ) -> (u64, Vec<SipAction>) {
        self.next_tx_id += 1;
        let tx_id = self.next_tx_id;
        let mut actions = Vec::new();

        let top_via = req.vias.first().expect("request must have via");
        let branch = top_via.branch.clone().expect("via must have branch");
        let method = req.method.clone();
        let is_invite = method == "INVITE";
        let protocol = req.transport.protocol;

        let wire_bytes = req.serialize();
        actions.push(SipAction::SendWire {
            target_addr: target_addr.clone(),
            protocol,
            bytes: wire_bytes,
        });

        if is_invite {
            if !protocol.is_reliable() {
                actions.push(SipAction::ArmTimer {
                    tx_id,
                    timer: SipTimerKind::TimerA,
                    at_mono_ms: now_mono_ms + T1_MS,
                });
            }
            actions.push(SipAction::ArmTimer {
                tx_id,
                timer: SipTimerKind::TimerB,
                at_mono_ms: now_mono_ms + 64 * T1_MS,
            });

            let client_tx = ClientTx {
                _id: tx_id,
                branch: branch.clone(),
                method: method.clone(),
                transport: protocol,
                target_addr,
                state: ClientTxState::Calling { request: req },
                retransmit_interval_ms: T1_MS,
            };
            self.client_txs.insert(tx_id, client_tx);
        } else {
            if !protocol.is_reliable() {
                actions.push(SipAction::ArmTimer {
                    tx_id,
                    timer: SipTimerKind::TimerE,
                    at_mono_ms: now_mono_ms + T1_MS,
                });
            }
            actions.push(SipAction::ArmTimer {
                tx_id,
                timer: SipTimerKind::TimerF,
                at_mono_ms: now_mono_ms + 64 * T1_MS,
            });

            let client_tx = ClientTx {
                _id: tx_id,
                branch: branch.clone(),
                method: method.clone(),
                transport: protocol,
                target_addr,
                state: ClientTxState::Trying { request: req },
                retransmit_interval_ms: T1_MS,
            };
            self.client_txs.insert(tx_id, client_tx);
        }

        self.client_keys.insert((branch, method), tx_id);
        (tx_id, actions)
    }

    fn handle_incoming_response(
        &mut self,
        resp: SipResponseData,
        now_mono_ms: u64,
    ) -> Vec<SipAction> {
        let mut actions = Vec::new();
        let top_via = match resp.vias.first() {
            Some(v) => v,
            None => return actions,
        };
        let branch = match &top_via.branch {
            Some(b) => b.clone(),
            None => return actions,
        };

        let method = resp.cseq.1.clone();
        let key = (branch, method);

        let &tx_id = match self.client_keys.get(&key) {
            Some(id) => id,
            None => return actions, // Dropped or handled at TU (e.g. 2xx retransmission)
        };

        let tx = match self.client_txs.get_mut(&tx_id) {
            Some(t) => t,
            None => return actions,
        };

        let is_invite = tx.method == "INVITE";
        let status = resp.status;

        if is_invite {
            if status < 200 {
                // Provisional: transition Calling -> Proceeding
                tx.state = ClientTxState::Proceeding { is_invite: true };
                actions.push(SipAction::DeliverResponseToClient {
                    tx_id,
                    response: resp,
                });
            } else if status < 300 {
                // 2xx response: TU handles ACK, client transaction terminates
                tx.state = ClientTxState::Terminated;
                actions.push(SipAction::DeliverResponseToClient {
                    tx_id,
                    response: resp,
                });
                actions.push(SipAction::TransactionTerminated { tx_id });
            } else {
                // 300-699: Client transaction automatically creates and sends ACK!
                let ack = SipRequestData {
                    method: "ACK".to_string(),
                    uri: resp.from.uri.clone(), // ACK uses destination
                    version: "SIP/2.0".to_string(),
                    vias: resp.vias.clone(),
                    from: resp.from.clone(),
                    to: resp.to.clone(),
                    call_id: resp.call_id.clone(),
                    cseq: (resp.cseq.0, "ACK".to_string()),
                    contacts: Vec::new(),
                    max_forwards: 70,
                    expires: None,
                    headers: Vec::new(),
                    body: Vec::new(),
                    transport: SipTransportMeta {
                        protocol: tx.transport,
                        source_address: "".into(),
                        destination_address: Some(tx.target_addr.clone()),
                        node_id: "".into(),
                        listener_id: None,
                    },
                };
                actions.push(SipAction::SendWire {
                    target_addr: tx.target_addr.clone(),
                    protocol: tx.transport,
                    bytes: ack.serialize(),
                });

                tx.state = ClientTxState::Completed { is_invite: true };
                actions.push(SipAction::DeliverResponseToClient {
                    tx_id,
                    response: resp,
                });

                if !tx.transport.is_reliable() {
                    actions.push(SipAction::ArmTimer {
                        tx_id,
                        timer: SipTimerKind::TimerD,
                        at_mono_ms: now_mono_ms + 64 * T1_MS,
                    });
                } else {
                    tx.state = ClientTxState::Terminated;
                    actions.push(SipAction::TransactionTerminated { tx_id });
                }
            }
        } else {
            // Non-INVITE response
            if status < 200 {
                tx.state = ClientTxState::Proceeding { is_invite: false };
                actions.push(SipAction::DeliverResponseToClient {
                    tx_id,
                    response: resp,
                });
            } else {
                tx.state = ClientTxState::Completed { is_invite: false };
                actions.push(SipAction::DeliverResponseToClient {
                    tx_id,
                    response: resp,
                });

                if !tx.transport.is_reliable() {
                    actions.push(SipAction::ArmTimer {
                        tx_id,
                        timer: SipTimerKind::TimerK,
                        at_mono_ms: now_mono_ms + T4_MS,
                    });
                } else {
                    tx.state = ClientTxState::Terminated;
                    actions.push(SipAction::TransactionTerminated { tx_id });
                }
            }
        }

        actions
    }

    /// Process a timer expiry (Timers A-K) in the state machine.
    pub fn handle_timer(
        &mut self,
        tx_id: u64,
        timer: SipTimerKind,
        now_mono_ms: u64,
    ) -> Vec<SipAction> {
        let mut actions = Vec::new();

        // Check if server transaction
        if let Some(tx) = self.server_txs.get_mut(&tx_id) {
            match timer {
                SipTimerKind::TimerG => {
                    if let ServerTxState::Completed {
                        final_response,
                        is_invite: true,
                    } = &tx.state
                    {
                        // Retransmit final response
                        actions.push(SipAction::SendWire {
                            target_addr: tx.source_addr.clone(),
                            protocol: tx.transport,
                            bytes: final_response.serialize(),
                        });
                        tx.retransmit_interval_ms = (tx.retransmit_interval_ms * 2).min(T2_MS);
                        actions.push(SipAction::ArmTimer {
                            tx_id,
                            timer: SipTimerKind::TimerG,
                            at_mono_ms: now_mono_ms + tx.retransmit_interval_ms,
                        });
                    }
                }
                SipTimerKind::TimerH => {
                    // Timer H fired: never received ACK, terminate transaction
                    tx.state = ServerTxState::Terminated;
                    actions.push(SipAction::TransactionTerminated { tx_id });
                }
                SipTimerKind::TimerI | SipTimerKind::TimerJ => {
                    tx.state = ServerTxState::Terminated;
                    actions.push(SipAction::TransactionTerminated { tx_id });
                }
                _ => {}
            }
            if tx.state == ServerTxState::Terminated {
                self.server_keys.remove(&(tx.branch.clone(), tx.method.clone()));
                self.server_txs.remove(&tx_id);
            }
            return actions;
        }

        // Check if client transaction
        if let Some(tx) = self.client_txs.get_mut(&tx_id) {
            match timer {
                SipTimerKind::TimerA => {
                    if let ClientTxState::Calling { request } = &tx.state {
                        actions.push(SipAction::SendWire {
                            target_addr: tx.target_addr.clone(),
                            protocol: tx.transport,
                            bytes: request.serialize(),
                        });
                        tx.retransmit_interval_ms *= 2;
                        actions.push(SipAction::ArmTimer {
                            tx_id,
                            timer: SipTimerKind::TimerA,
                            at_mono_ms: now_mono_ms + tx.retransmit_interval_ms,
                        });
                    }
                }
                SipTimerKind::TimerB => {
                    tx.state = ClientTxState::Terminated;
                    actions.push(SipAction::TransactionTerminated { tx_id });
                }
                SipTimerKind::TimerD | SipTimerKind::TimerK => {
                    tx.state = ClientTxState::Terminated;
                    actions.push(SipAction::TransactionTerminated { tx_id });
                }
                SipTimerKind::TimerE => {
                    if let ClientTxState::Trying { request } = &tx.state {
                        actions.push(SipAction::SendWire {
                            target_addr: tx.target_addr.clone(),
                            protocol: tx.transport,
                            bytes: request.serialize(),
                        });
                        tx.retransmit_interval_ms = (tx.retransmit_interval_ms * 2).min(T2_MS);
                        actions.push(SipAction::ArmTimer {
                            tx_id,
                            timer: SipTimerKind::TimerE,
                            at_mono_ms: now_mono_ms + tx.retransmit_interval_ms,
                        });
                    }
                }
                SipTimerKind::TimerF => {
                    tx.state = ClientTxState::Terminated;
                    actions.push(SipAction::TransactionTerminated { tx_id });
                }
                _ => {}
            }
            if tx.state == ClientTxState::Terminated {
                self.client_keys.remove(&(tx.branch.clone(), tx.method.clone()));
                self.client_txs.remove(&tx_id);
            }
        }

        actions
    }
}

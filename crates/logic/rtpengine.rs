// Copyright 2026 Deno Land Inc. Apache-2.0 license.

//! rtpengine NG bencode protocol codec.
//!
//! A pure sans-I/O codec for NG bencode messages used by Sipwise rtpengine.
//! Operates with zero third-party dependencies.
//!
//! NG protocol wire format:
//! `<cookie> <bencoded dictionary>`

use std::collections::BTreeMap;
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BencodeValue {
    Int(i64),
    Bytes(Vec<u8>),
    List(Vec<BencodeValue>),
    Dict(BTreeMap<Vec<u8>, BencodeValue>),
}

impl BencodeValue {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            BencodeValue::Bytes(b) => core::str::from_utf8(b).ok(),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            BencodeValue::Int(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_list(&self) -> Option<&[BencodeValue]> {
        match self {
            BencodeValue::List(l) => Some(l),
            _ => None,
        }
    }

    pub fn as_dict(&self) -> Option<&BTreeMap<Vec<u8>, BencodeValue>> {
        match self {
            BencodeValue::Dict(d) => Some(d),
            _ => None,
        }
    }

    pub fn dict_get(&self, key: &str) -> Option<&BencodeValue> {
        match self {
            BencodeValue::Dict(d) => d.get(key.as_bytes()),
            _ => None,
        }
    }

    pub fn dict_get_str(&self, key: &str) -> Option<&str> {
        self.dict_get(key).and_then(BencodeValue::as_str)
    }

    pub fn dict_get_i64(&self, key: &str) -> Option<i64> {
        self.dict_get(key).and_then(BencodeValue::as_i64)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RtpEngineError {
    InvalidFormat(&'static str),
    UnexpectedEof,
    TrailingBytes,
    Utf8Error,
}

impl fmt::Display for RtpEngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RtpEngineError::InvalidFormat(msg) => write!(f, "invalid bencode format: {msg}"),
            RtpEngineError::UnexpectedEof => write!(f, "unexpected end of bencode buffer"),
            RtpEngineError::TrailingBytes => write!(f, "trailing bytes after bencode root value"),
            RtpEngineError::Utf8Error => write!(f, "invalid UTF-8 in bencode string/cookie"),
        }
    }
}

/// Parses a single Bencode value from the input slice, returning the value and remaining slice.
pub fn parse_bencode_partial(input: &[u8]) -> Result<(BencodeValue, &[u8]), RtpEngineError> {
    if input.is_empty() {
        return Err(RtpEngineError::UnexpectedEof);
    }

    match input[0] {
        b'i' => {
            let end = input
                .iter()
                .position(|&b| b == b'e')
                .ok_or(RtpEngineError::UnexpectedEof)?;
            let num_str = core::str::from_utf8(&input[1..end]).map_err(|_| RtpEngineError::Utf8Error)?;
            let num = num_str
                .parse::<i64>()
                .map_err(|_| RtpEngineError::InvalidFormat("invalid integer value"))?;
            Ok((BencodeValue::Int(num), &input[end + 1..]))
        }
        b'l' => {
            let mut remaining = &input[1..];
            let mut list = Vec::new();
            while !remaining.is_empty() && remaining[0] != b'e' {
                let (val, rest) = parse_bencode_partial(remaining)?;
                list.push(val);
                remaining = rest;
            }
            if remaining.is_empty() {
                return Err(RtpEngineError::UnexpectedEof);
            }
            Ok((BencodeValue::List(list), &remaining[1..]))
        }
        b'd' => {
            let mut remaining = &input[1..];
            let mut dict = BTreeMap::new();
            while !remaining.is_empty() && remaining[0] != b'e' {
                let (key_val, rest) = parse_bencode_partial(remaining)?;
                let key = match key_val {
                    BencodeValue::Bytes(b) => b,
                    _ => return Err(RtpEngineError::InvalidFormat("dictionary key must be bytes")),
                };
                let (val, rest2) = parse_bencode_partial(rest)?;
                dict.insert(key, val);
                remaining = rest2;
            }
            if remaining.is_empty() {
                return Err(RtpEngineError::UnexpectedEof);
            }
            Ok((BencodeValue::Dict(dict), &remaining[1..]))
        }
        b'0'..=b'9' => {
            let colon_idx = input
                .iter()
                .position(|&b| b == b':')
                .ok_or(RtpEngineError::InvalidFormat("missing colon in string length"))?;
            let len_str =
                core::str::from_utf8(&input[..colon_idx]).map_err(|_| RtpEngineError::Utf8Error)?;
            let len = len_str
                .parse::<usize>()
                .map_err(|_| RtpEngineError::InvalidFormat("invalid string length"))?;
            let start = colon_idx + 1;
            let end = start
                .checked_add(len)
                .ok_or(RtpEngineError::InvalidFormat("string length overflow"))?;
            if end > input.len() {
                return Err(RtpEngineError::UnexpectedEof);
            }
            let bytes = input[start..end].to_vec();
            Ok((BencodeValue::Bytes(bytes), &input[end..]))
        }
        _ => Err(RtpEngineError::InvalidFormat("unknown bencode type marker")),
    }
}

/// Parses an entire slice into a single Bencode value, verifying no trailing bytes.
pub fn parse_bencode(input: &[u8]) -> Result<BencodeValue, RtpEngineError> {
    let (val, remaining) = parse_bencode_partial(input)?;
    if !remaining.is_empty() {
        return Err(RtpEngineError::TrailingBytes);
    }
    Ok(val)
}

/// Serializes a Bencode value into bytes.
pub fn serialize_bencode(val: &BencodeValue, out: &mut Vec<u8>) {
    match val {
        BencodeValue::Int(n) => {
            out.push(b'i');
            let s = n.to_string();
            out.extend_from_slice(s.as_bytes());
            out.push(b'e');
        }
        BencodeValue::Bytes(b) => {
            let len_str = b.len().to_string();
            out.extend_from_slice(len_str.as_bytes());
            out.push(b':');
            out.extend_from_slice(b);
        }
        BencodeValue::List(l) => {
            out.push(b'l');
            for item in l {
                serialize_bencode(item, out);
            }
            out.push(b'e');
        }
        BencodeValue::Dict(d) => {
            out.push(b'd');
            for (k, v) in d {
                let len_str = k.len().to_string();
                out.extend_from_slice(len_str.as_bytes());
                out.push(b':');
                out.extend_from_slice(k);
                serialize_bencode(v, out);
            }
            out.push(b'e');
        }
    }
}

/// Representation of an rtpengine NG protocol message: cookie + bencode payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RtpEngineMessage {
    pub cookie: String,
    pub payload: BencodeValue,
}

impl RtpEngineMessage {
    pub fn new(cookie: impl Into<String>, payload: BencodeValue) -> Self {
        Self {
            cookie: cookie.into(),
            payload,
        }
    }

    /// Parses an NG protocol packet `<cookie> <bencoded dictionary>`.
    pub fn parse(packet: &[u8]) -> Result<Self, RtpEngineError> {
        let space_idx = packet
            .iter()
            .position(|&b| b == b' ')
            .ok_or(RtpEngineError::InvalidFormat("missing space after cookie"))?;
        let cookie = core::str::from_utf8(&packet[..space_idx])
            .map_err(|_| RtpEngineError::Utf8Error)?
            .to_string();
        let payload = parse_bencode(&packet[space_idx + 1..])?;
        Ok(Self { cookie, payload })
    }

    /// Serializes to `<cookie> <bencoded dictionary>` bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(self.cookie.as_bytes());
        out.push(b' ');
        serialize_bencode(&self.payload, &mut out);
        out
    }
}

/// Helper builders for common rtpengine commands.
pub struct RtpEngineCommandBuilder;

impl RtpEngineCommandBuilder {
    pub fn ping(cookie: &str) -> RtpEngineMessage {
        let mut dict = BTreeMap::new();
        dict.insert(b"command".to_vec(), BencodeValue::Bytes(b"ping".to_vec()));
        RtpEngineMessage::new(cookie, BencodeValue::Dict(dict))
    }

    pub fn offer(
        cookie: &str,
        call_id: &str,
        from_tag: &str,
        sdp: &str,
        direction: Option<(&str, &str)>,
    ) -> RtpEngineMessage {
        let mut dict = BTreeMap::new();
        dict.insert(b"command".to_vec(), BencodeValue::Bytes(b"offer".to_vec()));
        dict.insert(
            b"call-id".to_vec(),
            BencodeValue::Bytes(call_id.as_bytes().to_vec()),
        );
        dict.insert(
            b"from-tag".to_vec(),
            BencodeValue::Bytes(from_tag.as_bytes().to_vec()),
        );
        dict.insert(b"sdp".to_vec(), BencodeValue::Bytes(sdp.as_bytes().to_vec()));
        if let Some((from_dir, to_dir)) = direction {
            let dir_list = vec![
                BencodeValue::Bytes(from_dir.as_bytes().to_vec()),
                BencodeValue::Bytes(to_dir.as_bytes().to_vec()),
            ];
            dict.insert(b"direction".to_vec(), BencodeValue::List(dir_list));
        }
        RtpEngineMessage::new(cookie, BencodeValue::Dict(dict))
    }

    pub fn answer(
        cookie: &str,
        call_id: &str,
        from_tag: &str,
        to_tag: &str,
        sdp: &str,
        direction: Option<(&str, &str)>,
    ) -> RtpEngineMessage {
        let mut dict = BTreeMap::new();
        dict.insert(b"command".to_vec(), BencodeValue::Bytes(b"answer".to_vec()));
        dict.insert(
            b"call-id".to_vec(),
            BencodeValue::Bytes(call_id.as_bytes().to_vec()),
        );
        dict.insert(
            b"from-tag".to_vec(),
            BencodeValue::Bytes(from_tag.as_bytes().to_vec()),
        );
        dict.insert(
            b"to-tag".to_vec(),
            BencodeValue::Bytes(to_tag.as_bytes().to_vec()),
        );
        dict.insert(b"sdp".to_vec(), BencodeValue::Bytes(sdp.as_bytes().to_vec()));
        if let Some((from_dir, to_dir)) = direction {
            let dir_list = vec![
                BencodeValue::Bytes(from_dir.as_bytes().to_vec()),
                BencodeValue::Bytes(to_dir.as_bytes().to_vec()),
            ];
            dict.insert(b"direction".to_vec(), BencodeValue::List(dir_list));
        }
        RtpEngineMessage::new(cookie, BencodeValue::Dict(dict))
    }

    pub fn delete(
        cookie: &str,
        call_id: &str,
        from_tag: Option<&str>,
        to_tag: Option<&str>,
    ) -> RtpEngineMessage {
        let mut dict = BTreeMap::new();
        dict.insert(b"command".to_vec(), BencodeValue::Bytes(b"delete".to_vec()));
        dict.insert(
            b"call-id".to_vec(),
            BencodeValue::Bytes(call_id.as_bytes().to_vec()),
        );
        if let Some(ft) = from_tag {
            dict.insert(
                b"from-tag".to_vec(),
                BencodeValue::Bytes(ft.as_bytes().to_vec()),
            );
        }
        if let Some(tt) = to_tag {
            dict.insert(
                b"to-tag".to_vec(),
                BencodeValue::Bytes(tt.as_bytes().to_vec()),
            );
        }
        RtpEngineMessage::new(cookie, BencodeValue::Dict(dict))
    }
}

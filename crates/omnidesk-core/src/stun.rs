//! Minimal RFC 5389 STUN binding client for server-reflexive candidate discovery.
//!
//! STUN is used only to discover a mapped address. It does not authenticate an
//! OmniDesk peer and cannot grant session or control authorization.

use std::{
    io::ErrorKind,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    time::Duration,
};

const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;
const MAGIC_COOKIE: u32 = 0x2112_A442;
const XOR_MAPPED_ADDRESS: u16 = 0x0020;
const HEADER_BYTES: usize = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StunError {
    Timeout,
    Io(ErrorKind),
    InvalidMessage,
    TransactionMismatch,
    MissingMappedAddress,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StunClient {
    timeout: Duration,
}

impl StunClient {
    #[must_use]
    pub const fn new(timeout: Duration) -> Self {
        Self { timeout }
    }

    /// Discovers the server-reflexive address observed by a STUN server.
    ///
    /// # Errors
    ///
    /// Returns a bounded timeout, I/O failure, malformed response, transaction
    /// mismatch, or missing XOR-MAPPED-ADDRESS.
    pub fn discover(
        &self,
        server: SocketAddr,
        transaction_id: [u8; 12],
    ) -> Result<SocketAddr, StunError> {
        let bind_address = match server.ip() {
            IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        };
        let socket = UdpSocket::bind(bind_address).map_err(io_error)?;
        socket
            .set_read_timeout(Some(self.timeout))
            .map_err(io_error)?;
        socket
            .set_write_timeout(Some(self.timeout))
            .map_err(io_error)?;
        socket.connect(server).map_err(io_error)?;

        let request = binding_request(transaction_id);
        socket.send(&request).map_err(io_error)?;

        let mut response = [0_u8; 512];
        let received = socket.recv(&mut response).map_err(map_receive_error)?;
        parse_binding_response(&response[..received], transaction_id)
    }
}

#[must_use]
pub fn binding_request(transaction_id: [u8; 12]) -> [u8; HEADER_BYTES] {
    let mut message = [0_u8; HEADER_BYTES];
    message[0..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    message[2..4].copy_from_slice(&0_u16.to_be_bytes());
    message[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    message[8..20].copy_from_slice(&transaction_id);
    message
}

/// Parses an RFC 5389 Binding Success response.
///
/// # Errors
///
/// Rejects malformed headers, mismatched transactions, invalid attributes, and
/// responses without XOR-MAPPED-ADDRESS.
pub fn parse_binding_response(
    message: &[u8],
    transaction_id: [u8; 12],
) -> Result<SocketAddr, StunError> {
    if message.len() < HEADER_BYTES {
        return Err(StunError::InvalidMessage);
    }
    if u16::from_be_bytes([message[0], message[1]]) != BINDING_SUCCESS {
        return Err(StunError::InvalidMessage);
    }
    if u32::from_be_bytes([message[4], message[5], message[6], message[7]]) != MAGIC_COOKIE {
        return Err(StunError::InvalidMessage);
    }
    if message[8..20] != transaction_id {
        return Err(StunError::TransactionMismatch);
    }

    let body_length = usize::from(u16::from_be_bytes([message[2], message[3]]));
    let end = HEADER_BYTES
        .checked_add(body_length)
        .ok_or(StunError::InvalidMessage)?;
    if end > message.len() {
        return Err(StunError::InvalidMessage);
    }

    let mut offset = HEADER_BYTES;
    while offset + 4 <= end {
        let attribute_type = u16::from_be_bytes([message[offset], message[offset + 1]]);
        let attribute_length =
            usize::from(u16::from_be_bytes([message[offset + 2], message[offset + 3]]));
        let value_start = offset + 4;
        let value_end = value_start
            .checked_add(attribute_length)
            .ok_or(StunError::InvalidMessage)?;
        if value_end > end {
            return Err(StunError::InvalidMessage);
        }

        if attribute_type == XOR_MAPPED_ADDRESS {
            return parse_xor_mapped(&message[value_start..value_end], transaction_id);
        }

        let padded = attribute_length
            .checked_add(3)
            .ok_or(StunError::InvalidMessage)?
            & !3;
        offset = value_start
            .checked_add(padded)
            .ok_or(StunError::InvalidMessage)?;
    }

    Err(StunError::MissingMappedAddress)
}

fn parse_xor_mapped(value: &[u8], transaction_id: [u8; 12]) -> Result<SocketAddr, StunError> {
    if value.len() < 4 || value[0] != 0 {
        return Err(StunError::InvalidMessage);
    }

    let cookie = MAGIC_COOKIE.to_be_bytes();
    let port = u16::from_be_bytes([value[2], value[3]]) ^ u16::from_be_bytes([cookie[0], cookie[1]]);

    match value[1] {
        0x01 if value.len() == 8 => {
            let octets = [
                value[4] ^ cookie[0],
                value[5] ^ cookie[1],
                value[6] ^ cookie[2],
                value[7] ^ cookie[3],
            ];
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port))
        }
        0x02 if value.len() == 20 => {
            let mut mask = [0_u8; 16];
            mask[0..4].copy_from_slice(&cookie);
            mask[4..16].copy_from_slice(&transaction_id);
            let mut octets = [0_u8; 16];
            for (index, octet) in octets.iter_mut().enumerate() {
                *octet = value[4 + index] ^ mask[index];
            }
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        _ => Err(StunError::InvalidMessage),
    }
}

fn map_receive_error(error: std::io::Error) -> StunError {
    match error.kind() {
        ErrorKind::WouldBlock | ErrorKind::TimedOut => StunError::Timeout,
        _ => io_error(error),
    }
}

fn io_error(error: std::io::Error) -> StunError {
    StunError::Io(error.kind())
}

#[cfg(test)]
mod tests {
    use std::{net::UdpSocket, thread};

    use super::*;

    fn success_response(transaction_id: [u8; 12], mapped: SocketAddr) -> Vec<u8> {
        let SocketAddr::V4(mapped) = mapped else {
            panic!("test uses IPv4");
        };
        let cookie = MAGIC_COOKIE.to_be_bytes();
        let xor_port = mapped.port() ^ u16::from_be_bytes([cookie[0], cookie[1]]);
        let ip = mapped.ip().octets();

        let mut attribute = vec![0_u8; 12];
        attribute[0..2].copy_from_slice(&XOR_MAPPED_ADDRESS.to_be_bytes());
        attribute[2..4].copy_from_slice(&8_u16.to_be_bytes());
        attribute[4] = 0;
        attribute[5] = 0x01;
        attribute[6..8].copy_from_slice(&xor_port.to_be_bytes());
        for index in 0..4 {
            attribute[8 + index] = ip[index] ^ cookie[index];
        }

        let mut response = vec![0_u8; HEADER_BYTES];
        response[0..2].copy_from_slice(&BINDING_SUCCESS.to_be_bytes());
        response[2..4].copy_from_slice(
            &u16::try_from(attribute.len())
                .expect("attribute length")
                .to_be_bytes(),
        );
        response[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
        response[8..20].copy_from_slice(&transaction_id);
        response.extend_from_slice(&attribute);
        response
    }

    #[test]
    fn binding_request_has_rfc5389_cookie_and_transaction() {
        let transaction_id = [5_u8; 12];
        let request = binding_request(transaction_id);

        assert_eq!(&request[0..2], &BINDING_REQUEST.to_be_bytes());
        assert_eq!(&request[2..4], &[0, 0]);
        assert_eq!(&request[4..8], &MAGIC_COOKIE.to_be_bytes());
        assert_eq!(&request[8..20], &transaction_id);
    }

    #[test]
    fn xor_mapped_ipv4_response_decodes() {
        let transaction_id = [9_u8; 12];
        let mapped: SocketAddr = "203.0.113.7:54321".parse().expect("mapped");
        let response = success_response(transaction_id, mapped);

        assert_eq!(
            parse_binding_response(&response, transaction_id),
            Ok(mapped)
        );
    }

    #[test]
    fn transaction_mismatch_is_rejected() {
        let response = success_response(
            [1_u8; 12],
            "203.0.113.7:54321".parse().expect("mapped"),
        );

        assert_eq!(
            parse_binding_response(&response, [2_u8; 12]),
            Err(StunError::TransactionMismatch)
        );
    }

    #[test]
    fn local_stun_server_discovers_mapped_candidate() {
        let server = UdpSocket::bind("127.0.0.1:0").expect("bind STUN server");
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("server timeout");
        let server_address = server.local_addr().expect("server address");
        let transaction_id = [4_u8; 12];

        let responder = thread::spawn(move || {
            let mut request = [0_u8; HEADER_BYTES];
            let (received, source) = server.recv_from(&mut request).expect("request");
            assert_eq!(received, HEADER_BYTES);
            assert_eq!(request, binding_request(transaction_id));
            let response = success_response(transaction_id, source);
            server.send_to(&response, source).expect("response");
            source
        });

        let client = StunClient::new(Duration::from_secs(2));
        let discovered = client
            .discover(server_address, transaction_id)
            .expect("STUN discovery");
        let observed = responder.join().expect("responder");

        assert_eq!(discovered, observed);
    }
}

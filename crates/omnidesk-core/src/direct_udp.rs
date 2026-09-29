//! Bounded UDP direct-path probing for M4 connectivity establishment.
//!
//! This module proves reachability to an explicitly selected peer candidate. It
//! is not peer authentication: the session layer must still complete Ed25519
//! authentication before remote control can be authorized.

use std::{
    io::ErrorKind,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    time::{Duration, Instant},
};

use omnidesk_protocol::{PROTOCOL_VERSION, signaling::ConnectionCandidate};

use crate::connectivity::ConnectionMetrics;

const PROBE_MAGIC: [u8; 4] = *b"KMOD";
const PROBE_BYTES: usize = 4 + 2 + 16 + 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectProbeError {
    Timeout,
    Io(ErrorKind),
    InvalidResponse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectProbeResult {
    pub peer: SocketAddr,
    pub metrics: ConnectionMetrics,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectProbe {
    timeout: Duration,
}

impl DirectProbe {
    #[must_use]
    pub const fn new(timeout: Duration) -> Self {
        Self { timeout }
    }

    /// Probes one selected UDP candidate with a versioned, session-bound echo.
    ///
    /// A successful probe establishes only candidate reachability. The caller
    /// must still perform the authenticated session handshake before granting
    /// any control permission.
    ///
    /// # Errors
    ///
    /// Returns a bounded timeout, I/O error, or invalid-response error.
    pub fn connect(
        &self,
        candidate: &ConnectionCandidate,
        session_id: [u8; 16],
        authentication_nonce: [u8; 32],
    ) -> Result<DirectProbeResult, DirectProbeError> {
        let bind_address = match candidate.address.ip() {
            IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        };
        let socket = UdpSocket::bind(bind_address).map_err(|error| io_error(&error))?;
        socket
            .set_read_timeout(Some(self.timeout))
            .map_err(|error| io_error(&error))?;
        socket
            .set_write_timeout(Some(self.timeout))
            .map_err(|error| io_error(&error))?;
        socket
            .connect(candidate.address)
            .map_err(|error| io_error(&error))?;

        let request = encode_probe(session_id, authentication_nonce);
        let started = Instant::now();
        socket.send(&request).map_err(|error| io_error(&error))?;

        let mut response = [0_u8; PROBE_BYTES];
        let received = socket.recv(&mut response).map_err(map_receive_error)?;
        if received != PROBE_BYTES || response != request {
            return Err(DirectProbeError::InvalidResponse);
        }

        Ok(DirectProbeResult {
            peer: candidate.address,
            metrics: ConnectionMetrics {
                connection_time: started.elapsed(),
                reconnect_time: None,
                attempts: 1,
            },
        })
    }

    /// Measures an initial direct probe followed by a fresh-nonce reconnect.
    ///
    /// # Errors
    ///
    /// Returns the first direct-probe failure and never fabricates a reconnect
    /// metric when the second reachability proof does not complete.
    pub fn connect_then_reconnect(
        &self,
        candidate: &ConnectionCandidate,
        session_id: [u8; 16],
        initial_nonce: [u8; 32],
        reconnect_nonce: [u8; 32],
    ) -> Result<DirectProbeResult, DirectProbeError> {
        let initial = self.connect(candidate, session_id, initial_nonce)?;
        let reconnected = self.connect(candidate, session_id, reconnect_nonce)?;

        Ok(DirectProbeResult {
            peer: candidate.address,
            metrics: ConnectionMetrics {
                connection_time: initial.metrics.connection_time,
                reconnect_time: Some(reconnected.metrics.connection_time),
                attempts: 2,
            },
        })
    }
}

#[must_use]
pub fn encode_probe(session_id: [u8; 16], authentication_nonce: [u8; 32]) -> [u8; PROBE_BYTES] {
    let mut packet = [0_u8; PROBE_BYTES];
    packet[0..4].copy_from_slice(&PROBE_MAGIC);
    packet[4..6].copy_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    packet[6..22].copy_from_slice(&session_id);
    packet[22..54].copy_from_slice(&authentication_nonce);
    packet
}

fn map_receive_error(error: std::io::Error) -> DirectProbeError {
    match error.kind() {
        ErrorKind::WouldBlock | ErrorKind::TimedOut => DirectProbeError::Timeout,
        _ => io_error(&error),
    }
}

fn io_error(error: &std::io::Error) -> DirectProbeError {
    DirectProbeError::Io(error.kind())
}

#[cfg(test)]
mod tests {
    use std::{net::UdpSocket, thread};

    use omnidesk_protocol::signaling::{CandidateKind, TransportProtocol};

    use super::*;

    fn candidate(address: SocketAddr) -> ConnectionCandidate {
        ConnectionCandidate {
            kind: CandidateKind::Host,
            transport: TransportProtocol::Udp,
            address,
            priority: 100,
        }
    }

    #[test]
    fn probe_packet_is_versioned_and_session_bound() {
        let packet = encode_probe([3_u8; 16], [7_u8; 32]);

        assert_eq!(&packet[0..4], b"KMOD");
        assert_eq!(&packet[4..6], &PROTOCOL_VERSION.to_be_bytes());
        assert_eq!(&packet[6..22], &[3_u8; 16]);
        assert_eq!(&packet[22..54], &[7_u8; 32]);
    }

    #[test]
    fn udp_direct_probe_verifies_exact_peer_echo_and_exports_metrics() {
        let peer = UdpSocket::bind("127.0.0.1:0").expect("bind peer");
        peer.set_read_timeout(Some(Duration::from_secs(2)))
            .expect("peer timeout");
        let address = peer.local_addr().expect("peer address");

        let responder = thread::spawn(move || {
            let mut request = [0_u8; PROBE_BYTES];
            let (received, source) = peer.recv_from(&mut request).expect("receive probe");
            assert_eq!(received, PROBE_BYTES);
            peer.send_to(&request, source).expect("echo probe");
        });

        let probe = DirectProbe::new(Duration::from_secs(2));
        let result = probe
            .connect(&candidate(address), [1_u8; 16], [2_u8; 32])
            .expect("direct probe");

        assert_eq!(result.peer, address);
        assert_eq!(result.metrics.attempts, 1);
        assert_eq!(result.metrics.reconnect_time, None);
        responder.join().expect("responder");
    }

    #[test]
    fn reconnect_uses_fresh_nonce_and_exports_reconnect_time() {
        let peer = UdpSocket::bind("127.0.0.1:0").expect("bind peer");
        peer.set_read_timeout(Some(Duration::from_secs(2)))
            .expect("peer timeout");
        let address = peer.local_addr().expect("peer address");

        let responder = thread::spawn(move || {
            let mut observed = Vec::new();
            for _ in 0..2 {
                let mut request = [0_u8; PROBE_BYTES];
                let (received, source) = peer.recv_from(&mut request).expect("receive probe");
                assert_eq!(received, PROBE_BYTES);
                observed.push(request);
                peer.send_to(&request, source).expect("echo probe");
            }
            observed
        });

        let probe = DirectProbe::new(Duration::from_secs(2));
        let result = probe
            .connect_then_reconnect(&candidate(address), [1_u8; 16], [2_u8; 32], [3_u8; 32])
            .expect("connect and reconnect");
        let observed = responder.join().expect("responder");

        assert_eq!(result.metrics.attempts, 2);
        assert!(result.metrics.reconnect_time.is_some());
        assert_ne!(observed[0], observed[1]);
        assert_eq!(&observed[0][22..54], &[2_u8; 32]);
        assert_eq!(&observed[1][22..54], &[3_u8; 32]);
    }

    #[test]
    fn modified_probe_response_is_rejected() {
        let peer = UdpSocket::bind("127.0.0.1:0").expect("bind peer");
        peer.set_read_timeout(Some(Duration::from_secs(2)))
            .expect("peer timeout");
        let address = peer.local_addr().expect("peer address");

        let responder = thread::spawn(move || {
            let mut request = [0_u8; PROBE_BYTES];
            let (_, source) = peer.recv_from(&mut request).expect("receive probe");
            request[PROBE_BYTES - 1] ^= 1;
            peer.send_to(&request, source).expect("send modified probe");
        });

        let probe = DirectProbe::new(Duration::from_secs(2));
        assert_eq!(
            probe.connect(&candidate(address), [1_u8; 16], [2_u8; 32]),
            Err(DirectProbeError::InvalidResponse)
        );
        responder.join().expect("responder");
    }
}

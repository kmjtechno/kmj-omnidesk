//! Transport-neutral signaling metadata for direct-connect negotiation.

use std::net::SocketAddr;

use crate::PROTOCOL_VERSION;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateKind {
    Host,
    ServerReflexive,
    Relay,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportProtocol {
    Udp,
    Tcp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionCandidate {
    pub kind: CandidateKind,
    pub transport: TransportProtocol,
    pub address: SocketAddr,
    pub priority: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignalingOffer {
    pub protocol_version: u16,
    pub session_id: [u8; 16],
    pub authentication_nonce: [u8; 32],
    pub candidates: Vec<ConnectionCandidate>,
}

impl SignalingOffer {
    #[must_use]
    pub const fn new(
        session_id: [u8; 16],
        authentication_nonce: [u8; 32],
        candidates: Vec<ConnectionCandidate>,
    ) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            session_id,
            authentication_nonce,
            candidates,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signaling_offer_is_versioned_and_session_bound() {
        let candidate = ConnectionCandidate {
            kind: CandidateKind::Host,
            transport: TransportProtocol::Udp,
            address: "127.0.0.1:4433".parse().expect("socket"),
            priority: 100,
        };
        let offer = SignalingOffer::new([1_u8; 16], [2_u8; 32], vec![candidate.clone()]);

        assert_eq!(offer.protocol_version, PROTOCOL_VERSION);
        assert_eq!(offer.session_id, [1_u8; 16]);
        assert_eq!(offer.authentication_nonce, [2_u8; 32]);
        assert_eq!(offer.candidates, vec![candidate]);
    }
}

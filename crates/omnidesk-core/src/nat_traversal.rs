//! Same-socket STUN mapping observations for M4 NAT traversal.
//!
//! This deliberately reports observed mapping behavior rather than claiming a
//! complete NAT type. Full RFC 5780 behavior discovery and public Internet/NAT
//! device verification remain separate test-matrix work.

use std::net::{SocketAddr, UdpSocket};

use omnidesk_protocol::signaling::{CandidateKind, ConnectionCandidate, TransportProtocol};

use crate::stun::{StunClient, StunError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MappingBehavior {
    EndpointIndependentObserved,
    EndpointDependentObserved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MappingObservation {
    pub primary: SocketAddr,
    pub secondary: SocketAddr,
    pub behavior: MappingBehavior,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatTraversalError {
    Bind,
    Primary(StunError),
    Secondary(StunError),
}

impl MappingObservation {
    #[must_use]
    pub const fn candidate(self, priority: u32) -> ConnectionCandidate {
        ConnectionCandidate {
            kind: CandidateKind::ServerReflexive,
            transport: TransportProtocol::Udp,
            address: self.primary,
            priority,
        }
    }
}

#[must_use]
pub fn classify_mapping(primary: SocketAddr, secondary: SocketAddr) -> MappingBehavior {
    if primary == secondary {
        MappingBehavior::EndpointIndependentObserved
    } else {
        MappingBehavior::EndpointDependentObserved
    }
}

/// Queries two STUN servers from one UDP socket and compares their observations.
///
/// # Errors
///
/// Returns bind failure or the exact primary/secondary STUN failure.
pub fn observe_mapping(
    client: &StunClient,
    primary_server: SocketAddr,
    secondary_server: SocketAddr,
    primary_transaction: [u8; 12],
    secondary_transaction: [u8; 12],
) -> Result<MappingObservation, NatTraversalError> {
    let bind = if primary_server.is_ipv4() && secondary_server.is_ipv4() {
        "0.0.0.0:0"
    } else if primary_server.is_ipv6() && secondary_server.is_ipv6() {
        "[::]:0"
    } else {
        return Err(NatTraversalError::Bind);
    };
    let socket = UdpSocket::bind(bind).map_err(|_| NatTraversalError::Bind)?;
    let primary = client
        .discover_from(&socket, primary_server, primary_transaction)
        .map_err(NatTraversalError::Primary)?;
    let secondary = client
        .discover_from(&socket, secondary_server, secondary_transaction)
        .map_err(NatTraversalError::Secondary)?;

    Ok(MappingObservation {
        primary,
        secondary,
        behavior: classify_mapping(primary, secondary),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_observations_are_endpoint_independent() {
        let mapped = "203.0.113.10:50000".parse().expect("mapped");
        assert_eq!(
            classify_mapping(mapped, mapped),
            MappingBehavior::EndpointIndependentObserved
        );
    }

    #[test]
    fn changed_observation_is_endpoint_dependent() {
        let first = "203.0.113.10:50000".parse().expect("first");
        let second = "203.0.113.10:50001".parse().expect("second");
        assert_eq!(
            classify_mapping(first, second),
            MappingBehavior::EndpointDependentObserved
        );
    }

    #[test]
    fn observation_becomes_server_reflexive_udp_candidate() {
        let mapped = "203.0.113.10:50000".parse().expect("mapped");
        let observation = MappingObservation {
            primary: mapped,
            secondary: mapped,
            behavior: MappingBehavior::EndpointIndependentObserved,
        };
        let candidate = observation.candidate(250);

        assert_eq!(candidate.kind, CandidateKind::ServerReflexive);
        assert_eq!(candidate.transport, TransportProtocol::Udp);
        assert_eq!(candidate.address, mapped);
        assert_eq!(candidate.priority, 250);
    }
}

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
    InvalidObservationSetup,
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
/// Returns a configuration error, bind failure or the exact STUN failure.
/// A single server cannot independently confirm endpoint mapping behaviour.
pub fn observe_mapping(
    client: &StunClient,
    primary_server: SocketAddr,
    secondary_server: SocketAddr,
    primary_transaction: [u8; 12],
    secondary_transaction: [u8; 12],
) -> Result<MappingObservation, NatTraversalError> {
    // An identical server probes the same endpoint twice, yielding a false
    // EndpointIndependentObserved result irrespective of NAT behaviour.
    // Separate transaction IDs also prevent response replay across probes.
    // Reject these configurations before binding or transmitting UDP.
    if primary_server == secondary_server || primary_transaction == secondary_transaction {
        return Err(NatTraversalError::InvalidObservationSetup);
    }
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
    fn rejects_nonindependent_probe_setup_without_udp() {
        let client = StunClient::new(std::time::Duration::from_millis(10));
        let first: SocketAddr = "127.0.0.1:9".parse().expect("server");
        let second: SocketAddr = "127.0.0.1:10".parse().expect("other server");
        assert_eq!(
            observe_mapping(&client, first, first, [1; 12], [2; 12]),
            Err(NatTraversalError::InvalidObservationSetup)
        );
        assert_eq!(
            observe_mapping(&client, first, second, [1; 12], [1; 12]),
            Err(NatTraversalError::InvalidObservationSetup)
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

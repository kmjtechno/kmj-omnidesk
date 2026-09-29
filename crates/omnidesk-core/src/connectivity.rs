//! Direct-first candidate selection and connection metrics.

use std::time::Duration;

use omnidesk_protocol::signaling::{CandidateKind, ConnectionCandidate, TransportProtocol};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectivityError {
    NoDirectCandidate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionMetrics {
    pub connection_time: Duration,
    pub reconnect_time: Option<Duration>,
    pub attempts: u32,
}

#[derive(Debug, Default)]
pub struct DirectPathSelector;

impl DirectPathSelector {
    /// Selects the highest-priority direct candidate without silently falling
    /// back to relay.
    ///
    /// UDP is preferred over TCP when priorities are equal. Relay candidates
    /// are deliberately excluded here so relay fallback remains an explicit M5
    /// policy decision.
    ///
    /// # Errors
    ///
    /// Returns `ConnectivityError::NoDirectCandidate` when only relay or no
    /// candidates are available.
    pub fn select(
        candidates: &[ConnectionCandidate],
    ) -> Result<&ConnectionCandidate, ConnectivityError> {
        candidates
            .iter()
            .filter(|candidate| {
                matches!(
                    candidate.kind,
                    CandidateKind::Host | CandidateKind::ServerReflexive
                )
            })
            .max_by_key(|candidate| {
                (
                    candidate.priority,
                    u8::from(candidate.transport == TransportProtocol::Udp),
                )
            })
            .ok_or(ConnectivityError::NoDirectCandidate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(
        kind: CandidateKind,
        transport: TransportProtocol,
        port: u16,
        priority: u32,
    ) -> ConnectionCandidate {
        ConnectionCandidate {
            kind,
            transport,
            address: format!("127.0.0.1:{port}").parse().expect("socket"),
            priority,
        }
    }

    #[test]
    fn highest_priority_direct_candidate_wins() {
        let host = candidate(CandidateKind::Host, TransportProtocol::Udp, 4000, 100);
        let reflexive = candidate(
            CandidateKind::ServerReflexive,
            TransportProtocol::Udp,
            5000,
            200,
        );
        let relay = candidate(CandidateKind::Relay, TransportProtocol::Udp, 6000, 500);

        assert_eq!(
            DirectPathSelector::select(&[host, reflexive.clone(), relay]),
            Ok(&reflexive)
        );
    }

    #[test]
    fn udp_wins_equal_priority_without_hiding_priority() {
        let tcp = candidate(CandidateKind::Host, TransportProtocol::Tcp, 4000, 100);
        let udp = candidate(CandidateKind::Host, TransportProtocol::Udp, 5000, 100);

        assert_eq!(DirectPathSelector::select(&[tcp, udp.clone()]), Ok(&udp));
    }

    #[test]
    fn relay_is_not_silently_selected_as_direct() {
        let relay = candidate(CandidateKind::Relay, TransportProtocol::Udp, 6000, 500);

        assert_eq!(
            DirectPathSelector::select(&[relay]),
            Err(ConnectivityError::NoDirectCandidate)
        );
    }
}

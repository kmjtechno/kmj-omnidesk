//! Direct-first candidate attempt orchestration with explicit failure reporting.

use std::net::SocketAddr;

use omnidesk_protocol::signaling::{CandidateKind, ConnectionCandidate, TransportProtocol};

use crate::{
    connectivity::{ConnectionMetrics, DirectConnectStats},
    direct_udp::{DirectProbe, DirectProbeError},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectAttemptSuccess {
    pub peer: SocketAddr,
    pub metrics: ConnectionMetrics,
    pub stats: DirectConnectStats,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectAttemptError {
    NoUsableDirectCandidate,
    AllDirectAttemptsFailed {
        attempts: u32,
        last_error: DirectProbeError,
    },
}

pub trait CandidateProbe {
    /// Probes one direct candidate for bounded reachability.
    ///
    /// # Errors
    ///
    /// Returns the concrete direct-probe failure without converting it into a
    /// relay or alternate-transport decision.
    fn probe(
        &self,
        candidate: &ConnectionCandidate,
        session_id: [u8; 16],
        authentication_nonce: [u8; 32],
    ) -> Result<(SocketAddr, ConnectionMetrics), DirectProbeError>;
}

impl CandidateProbe for DirectProbe {
    fn probe(
        &self,
        candidate: &ConnectionCandidate,
        session_id: [u8; 16],
        authentication_nonce: [u8; 32],
    ) -> Result<(SocketAddr, ConnectionMetrics), DirectProbeError> {
        let result = self.connect(candidate, session_id, authentication_nonce)?;
        Ok((result.peer, result.metrics))
    }
}

/// Attempts direct UDP candidates by descending priority.
///
/// Relay and TCP candidates are deliberately not hidden inside this M4 path.
/// Relay fallback remains an explicit M5 policy.
///
/// # Errors
///
/// Returns an explicit no-candidate error or the final direct-probe failure
/// together with the number of attempted direct candidates.
pub fn connect_direct_candidates<P: CandidateProbe>(
    probe: &P,
    candidates: &[ConnectionCandidate],
    session_id: [u8; 16],
    authentication_nonce: [u8; 32],
) -> Result<DirectAttemptSuccess, DirectAttemptError> {
    let mut direct = candidates
        .iter()
        .filter(|candidate| {
            matches!(
                candidate.kind,
                CandidateKind::Host | CandidateKind::ServerReflexive
            ) && candidate.transport == TransportProtocol::Udp
        })
        .collect::<Vec<_>>();
    direct.sort_by_key(|candidate| std::cmp::Reverse(candidate.priority));

    if direct.is_empty() {
        return Err(DirectAttemptError::NoUsableDirectCandidate);
    }

    let mut stats = DirectConnectStats::default();
    let mut last_error = DirectProbeError::InvalidResponse;
    for candidate in direct {
        match probe.probe(candidate, session_id, authentication_nonce) {
            Ok((peer, metrics)) => {
                stats.record(true);
                return Ok(DirectAttemptSuccess {
                    peer,
                    metrics,
                    stats,
                });
            }
            Err(error) => {
                stats.record(false);
                last_error = error;
            }
        }
    }

    Err(DirectAttemptError::AllDirectAttemptsFailed {
        attempts: stats.attempts(),
        last_error,
    })
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, time::Duration};

    use super::*;

    struct ScriptedProbe {
        failures_before_success: u32,
        calls: Cell<u32>,
    }

    impl CandidateProbe for ScriptedProbe {
        fn probe(
            &self,
            candidate: &ConnectionCandidate,
            _session_id: [u8; 16],
            _authentication_nonce: [u8; 32],
        ) -> Result<(SocketAddr, ConnectionMetrics), DirectProbeError> {
            let call = self.calls.get() + 1;
            self.calls.set(call);
            if call <= self.failures_before_success {
                return Err(DirectProbeError::Timeout);
            }

            Ok((
                candidate.address,
                ConnectionMetrics {
                    connection_time: Duration::from_millis(5),
                    reconnect_time: None,
                    attempts: 1,
                },
            ))
        }
    }

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
    fn next_direct_candidate_is_attempted_after_failure() {
        let candidates = [
            candidate(CandidateKind::Host, TransportProtocol::Udp, 4000, 200),
            candidate(
                CandidateKind::ServerReflexive,
                TransportProtocol::Udp,
                5000,
                100,
            ),
        ];
        let probe = ScriptedProbe {
            failures_before_success: 1,
            calls: Cell::new(0),
        };

        let result = connect_direct_candidates(&probe, &candidates, [1_u8; 16], [2_u8; 32])
            .expect("second candidate succeeds");

        assert_eq!(result.peer, candidates[1].address);
        assert_eq!(result.stats.attempts(), 2);
        assert_eq!(result.stats.successes(), 1);
        assert_eq!(result.stats.success_rate_bps(), 5_000);
    }

    #[test]
    fn relay_and_tcp_are_not_silently_attempted() {
        let candidates = [
            candidate(CandidateKind::Relay, TransportProtocol::Udp, 6000, 500),
            candidate(CandidateKind::Host, TransportProtocol::Tcp, 7000, 400),
        ];
        let probe = ScriptedProbe {
            failures_before_success: 0,
            calls: Cell::new(0),
        };

        assert_eq!(
            connect_direct_candidates(&probe, &candidates, [1_u8; 16], [2_u8; 32]),
            Err(DirectAttemptError::NoUsableDirectCandidate)
        );
        assert_eq!(probe.calls.get(), 0);
    }

    #[test]
    fn all_direct_failures_report_attempt_count_and_last_error() {
        let candidates = [
            candidate(CandidateKind::Host, TransportProtocol::Udp, 4000, 200),
            candidate(
                CandidateKind::ServerReflexive,
                TransportProtocol::Udp,
                5000,
                100,
            ),
        ];
        let probe = ScriptedProbe {
            failures_before_success: 2,
            calls: Cell::new(0),
        };

        assert_eq!(
            connect_direct_candidates(&probe, &candidates, [1_u8; 16], [2_u8; 32]),
            Err(DirectAttemptError::AllDirectAttemptsFailed {
                attempts: 2,
                last_error: DirectProbeError::Timeout,
            })
        );
    }
}

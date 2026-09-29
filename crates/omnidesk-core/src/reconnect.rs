//! Bounded direct-path reconnect policy for M4.

use std::time::{Duration, Instant};

use omnidesk_protocol::signaling::ConnectionCandidate;

use crate::direct_connect::{
    CandidateProbe, DirectAttemptError, DirectAttemptSuccess, connect_direct_candidates,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReconnectPolicy {
    pub max_rounds: u32,
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReconnectSuccess {
    pub direct: DirectAttemptSuccess,
    pub rounds: u32,
    pub candidate_attempts: u32,
    pub reconnect_time: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconnectError {
    MissingFreshNonce,
    Exhausted {
        rounds: u32,
        candidate_attempts: u32,
        last_error: DirectAttemptError,
    },
}

pub trait ReconnectSleeper {
    fn sleep(&self, duration: Duration);
}

#[derive(Debug, Default)]
pub struct ThreadSleeper;

impl ReconnectSleeper for ThreadSleeper {
    fn sleep(&self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

impl ReconnectPolicy {
    #[must_use]
    pub fn backoff_for_round(self, round: u32) -> Duration {
        if round <= 1 {
            return Duration::ZERO;
        }

        let shifts = round.saturating_sub(2).min(31);
        let factor = 1_u32 << shifts;
        self.initial_backoff
            .checked_mul(factor)
            .unwrap_or(self.max_backoff)
            .min(self.max_backoff)
    }
}

/// Re-attempts direct candidates with a fresh caller-supplied nonce per round.
///
/// # Errors
///
/// Fails closed when a fresh nonce is unavailable or when the bounded reconnect
/// budget is exhausted. Relay fallback remains an explicit M5 decision.
pub fn reconnect_direct<P: CandidateProbe, S: ReconnectSleeper>(
    probe: &P,
    sleeper: &S,
    policy: ReconnectPolicy,
    candidates: &[ConnectionCandidate],
    session_id: [u8; 16],
    fresh_nonces: &[[u8; 32]],
) -> Result<ReconnectSuccess, ReconnectError> {
    let started = Instant::now();
    let mut candidate_attempts = 0_u32;
    let mut last_error = DirectAttemptError::NoUsableDirectCandidate;

    for round in 1..=policy.max_rounds {
        let nonce = *fresh_nonces
            .get(usize::try_from(round - 1).expect("round index"))
            .ok_or(ReconnectError::MissingFreshNonce)?;
        sleeper.sleep(policy.backoff_for_round(round));

        match connect_direct_candidates(probe, candidates, session_id, nonce) {
            Ok(direct) => {
                candidate_attempts = candidate_attempts.saturating_add(direct.stats.attempts());
                return Ok(ReconnectSuccess {
                    direct,
                    rounds: round,
                    candidate_attempts,
                    reconnect_time: started.elapsed(),
                });
            }
            Err(error) => {
                candidate_attempts =
                    candidate_attempts.saturating_add(candidate_attempt_count(error));
                last_error = error;
            }
        }
    }

    Err(ReconnectError::Exhausted {
        rounds: policy.max_rounds,
        candidate_attempts,
        last_error,
    })
}

const fn candidate_attempt_count(error: DirectAttemptError) -> u32 {
    match error {
        DirectAttemptError::NoUsableDirectCandidate => 0,
        DirectAttemptError::AllDirectAttemptsFailed { attempts, .. } => attempts,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cell::{Cell, RefCell},
        net::SocketAddr,
    };

    use omnidesk_protocol::signaling::{CandidateKind, TransportProtocol};

    use crate::{
        connectivity::ConnectionMetrics,
        direct_udp::DirectProbeError,
    };

    use super::*;

    struct ScriptedProbe {
        failures: u32,
        calls: Cell<u32>,
        nonces: RefCell<Vec<[u8; 32]>>,
    }

    impl CandidateProbe for ScriptedProbe {
        fn probe(
            &self,
            candidate: &ConnectionCandidate,
            _session_id: [u8; 16],
            nonce: [u8; 32],
        ) -> Result<(SocketAddr, ConnectionMetrics), DirectProbeError> {
            self.nonces.borrow_mut().push(nonce);
            let call = self.calls.get() + 1;
            self.calls.set(call);
            if call <= self.failures {
                return Err(DirectProbeError::Timeout);
            }
            Ok((
                candidate.address,
                ConnectionMetrics {
                    connection_time: Duration::from_millis(4),
                    reconnect_time: None,
                    attempts: 1,
                },
            ))
        }
    }

    #[derive(Default)]
    struct RecordingSleeper {
        durations: RefCell<Vec<Duration>>,
    }

    impl ReconnectSleeper for RecordingSleeper {
        fn sleep(&self, duration: Duration) {
            self.durations.borrow_mut().push(duration);
        }
    }

    fn candidate() -> ConnectionCandidate {
        ConnectionCandidate {
            kind: CandidateKind::Host,
            transport: TransportProtocol::Udp,
            address: "127.0.0.1:4000".parse().expect("candidate"),
            priority: 100,
        }
    }

    fn policy() -> ReconnectPolicy {
        ReconnectPolicy {
            max_rounds: 4,
            initial_backoff: Duration::from_millis(50),
            max_backoff: Duration::from_millis(120),
        }
    }

    #[test]
    fn backoff_is_bounded_and_first_round_is_immediate() {
        let policy = policy();
        assert_eq!(policy.backoff_for_round(1), Duration::ZERO);
        assert_eq!(policy.backoff_for_round(2), Duration::from_millis(50));
        assert_eq!(policy.backoff_for_round(3), Duration::from_millis(100));
        assert_eq!(policy.backoff_for_round(4), Duration::from_millis(120));
        assert_eq!(policy.backoff_for_round(20), Duration::from_millis(120));
    }

    #[test]
    fn reconnect_uses_fresh_nonce_each_round_and_recovers() {
        let probe = ScriptedProbe {
            failures: 2,
            calls: Cell::new(0),
            nonces: RefCell::new(Vec::new()),
        };
        let sleeper = RecordingSleeper::default();
        let nonces = [[1_u8; 32], [2_u8; 32], [3_u8; 32], [4_u8; 32]];

        let result = reconnect_direct(
            &probe,
            &sleeper,
            policy(),
            &[candidate()],
            [9_u8; 16],
            &nonces,
        )
        .expect("third round recovers");

        assert_eq!(result.rounds, 3);
        assert_eq!(result.candidate_attempts, 3);
        assert_eq!(&*probe.nonces.borrow(), &nonces[..3]);
        assert_eq!(
            &*sleeper.durations.borrow(),
            &[
                Duration::ZERO,
                Duration::from_millis(50),
                Duration::from_millis(100)
            ]
        );
    }

    #[test]
    fn missing_fresh_nonce_fails_closed() {
        let probe = ScriptedProbe {
            failures: 4,
            calls: Cell::new(0),
            nonces: RefCell::new(Vec::new()),
        };
        let sleeper = RecordingSleeper::default();

        assert_eq!(
            reconnect_direct(
                &probe,
                &sleeper,
                policy(),
                &[candidate()],
                [9_u8; 16],
                &[[1_u8; 32]],
            ),
            Err(ReconnectError::MissingFreshNonce)
        );
    }
}

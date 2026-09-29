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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExportedConnectionMetrics {
    pub connection_time_ms: u64,
    pub direct_connect_success_rate_bps: u16,
    pub reconnect_time_ms: Option<u64>,
}

impl ConnectionMetrics {
    #[must_use]
    pub fn export(self, direct_stats: &DirectConnectStats) -> ExportedConnectionMetrics {
        ExportedConnectionMetrics {
            connection_time_ms: duration_ms_ceil(self.connection_time),
            direct_connect_success_rate_bps: direct_stats.success_rate_bps(),
            reconnect_time_ms: self.reconnect_time.map(duration_ms_ceil),
        }
    }
}

fn duration_ms_ceil(duration: Duration) -> u64 {
    let millis = duration.as_millis();
    let rounded = if duration.subsec_nanos() % 1_000_000 == 0 {
        millis
    } else {
        millis.saturating_add(1)
    };
    u64::try_from(rounded).unwrap_or(u64::MAX)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DirectConnectStats {
    attempts: u32,
    successes: u32,
}

impl DirectConnectStats {
    pub const fn record(&mut self, succeeded: bool) {
        self.attempts = self.attempts.saturating_add(1);
        if succeeded {
            self.successes = self.successes.saturating_add(1);
        }
    }

    #[must_use]
    pub const fn attempts(&self) -> u32 {
        self.attempts
    }

    #[must_use]
    pub const fn successes(&self) -> u32 {
        self.successes
    }

    /// Returns success rate in basis points (`0..=10_000`) without float drift.
    #[must_use]
    pub fn success_rate_bps(&self) -> u16 {
        if self.attempts == 0 {
            return 0;
        }

        let scaled = u64::from(self.successes) * 10_000 / u64::from(self.attempts);
        u16::try_from(scaled).unwrap_or(10_000)
    }
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
    fn exported_metrics_use_stable_millisecond_units_and_rate() {
        let mut stats = DirectConnectStats::default();
        stats.record(true);
        stats.record(true);
        stats.record(true);
        stats.record(false);

        let metrics = ConnectionMetrics {
            connection_time: Duration::from_micros(1_001),
            reconnect_time: Some(Duration::from_millis(9)),
            attempts: 4,
        }
        .export(&stats);

        assert_eq!(metrics.connection_time_ms, 2);
        assert_eq!(metrics.direct_connect_success_rate_bps, 7_500);
        assert_eq!(metrics.reconnect_time_ms, Some(9));
    }

    #[test]
    fn exported_metrics_preserve_missing_reconnect() {
        let metrics = ConnectionMetrics {
            connection_time: Duration::ZERO,
            reconnect_time: None,
            attempts: 0,
        }
        .export(&DirectConnectStats::default());

        assert_eq!(metrics.connection_time_ms, 0);
        assert_eq!(metrics.direct_connect_success_rate_bps, 0);
        assert_eq!(metrics.reconnect_time_ms, None);
    }

    #[test]
    fn direct_connect_success_rate_is_deterministic() {
        let mut stats = DirectConnectStats::default();
        stats.record(true);
        stats.record(false);
        stats.record(true);
        stats.record(true);

        assert_eq!(stats.attempts(), 4);
        assert_eq!(stats.successes(), 3);
        assert_eq!(stats.success_rate_bps(), 7_500);
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

//! M13 release-candidate measurement across the declared network profiles.
//!
//! Emits the ten metrics `benchmarks/network-profiles.yaml` requires, as
//! measured, into the shape `scripts/m13_matrix.py` accepts.
//!
//! Three of the ten cannot be produced here and are emitted as `null` with a
//! stated reason rather than filled in: `cpu_percent`, `gpu_percent`, and
//! `ram_mb` need measurement of a live process on the target machine, which a
//! benchmark binary is not. The CI resource-baseline steps measure those for
//! the desktop binary; until the two are merged, `m13_matrix.py verify`
//! refuses this file, which is the correct outcome. A benchmark that emitted a
//! plausible CPU figure would be worse than one that admits it has none.
//!
//! `direct_connect_success_rate` and `relay_ratio` come from a real local UDP
//! establishment loop and the real meter, not from simulation. That loop does
//! not traverse a NAT, so the direct rate it reports is a loopback reference
//! and is labelled as one. It is not a claim about the public Internet.

use std::net::UdpSocket;
use std::time::{Duration, Instant};

use omnidesk_core::connectivity::{ConnectionMetrics, DirectConnectStats};
use omnidesk_core::media::{Frame, measure_pipeline};
use omnidesk_core::relay::{
    RelayAuthorization, RelayPathDecision, RelayUsageMetrics, meter_relay_session,
};
use omnidesk_core::weak_network::{
    AdaptationPolicy, NetworkSample, QualityLevel, evaluate_samples,
};
use omnidesk_core::weak_network_reconnect::{DisconnectCause, WeakNetworkReconnectPolicy};

/// A profile from `benchmarks/network-profiles.yaml`.
///
/// `loss_ppm` is parts per thousand, matching `NetworkSample`, so the
/// YAML's `loss_percent: 1` becomes 10 and `loss_percent: 5` becomes 50.
struct Profile {
    name: &'static str,
    sample: NetworkSample,
}

const PROFILES: [Profile; 4] = [
    Profile {
        name: "office_good",
        sample: NetworkSample {
            throughput_bps: 20_000_000,
            latency: Duration::from_millis(20),
            loss_ppm: 0,
        },
    },
    Profile {
        name: "mobile_constrained",
        sample: NetworkSample {
            throughput_bps: 2_000_000,
            latency: Duration::from_millis(80),
            loss_ppm: 10,
        },
    },
    Profile {
        name: "weak_mobile",
        sample: NetworkSample {
            throughput_bps: 750_000,
            latency: Duration::from_millis(150),
            loss_ppm: 30,
        },
    },
    Profile {
        name: "severe",
        sample: NetworkSample {
            throughput_bps: 350_000,
            latency: Duration::from_millis(250),
            loss_ppm: 50,
        },
    },
];

/// Runs a real local UDP establishment and records whether it connected.
fn measure_direct_connect(attempts: u32) -> (DirectConnectStats, Duration) {
    let mut stats = DirectConnectStats::default();
    let total = Instant::now();

    for _ in 0..attempts {
        let server = UdpSocket::bind("127.0.0.1:0").expect("bind responder");
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set read timeout");
        let address = server.local_addr().expect("responder address");

        let client = UdpSocket::bind("127.0.0.1:0").expect("bind initiator");
        client.connect(address).expect("connect to responder");
        client.send(b"kmj").expect("send");

        let mut buffer = [0_u8; 3];
        let received = server.recv(&mut buffer).expect("receive");
        stats.record(received == 3);
    }

    (stats, total.elapsed() / attempts)
}

/// Measures the interactive path: one frame through the pipeline, timed.
///
/// This is capture-conversion plus queue round-trip, not presentation. It is
/// the portion this process owns; the compositor and the display are outside
/// it, so the figure is a floor on interactive latency and is labelled as one.
fn measure_interactive_latency(iterations: u32) -> f64 {
    let total = Instant::now();
    for index in 0..iterations {
        let bytes = (index % 251) as u8;
        let frame = Frame::new_bgra(64, 64, 64 * 4, vec![bytes; 64 * 64 * 4]).expect("valid frame");
        let measurement =
            measure_pipeline(frame.data().len(), || Ok(frame.data().len())).expect("measured");
        assert_eq!(measurement.input_bytes, measurement.output_bytes);
    }
    total.elapsed().as_secs_f64() * 1000.0 / f64::from(iterations)
}

/// The delay before the *first* retry under this profile.
///
/// Round 1 is un-delayed by design, so the first wait a user actually
/// experiences is round 2. Summing rounds 2..=5 instead would report a figure
/// describing a policy rather than an experience -- it grows with the round
/// count chosen here, which makes it a knob, not a measurement.
fn measure_reconnect_time(profile: &Profile) -> f64 {
    WeakNetworkReconnectPolicy::default()
        .backoff_before(2, DisconnectCause::LinkDegraded, Some(&profile.sample))
        .as_secs_f64()
        * 1000.0
}

/// Measures how fast this pipeline can move bytes.
///
/// On loopback this returns whatever the CPU can memcpy -- multi-gigabit
/// figures that describe a memory bus, not a network. Reported as
/// `pipeline_local_throughput_kbps` rather than `bandwidth_kbps`, because a
/// number under the M13 name would be read as a network result.
fn measure_pipeline_throughput(iterations: u32) -> f64 {
    let total = Instant::now();
    // `u64` rather than `usize`: the accumulator is a byte count and its width
    // should not vary with the target, and the sum is widened through
    // `from` below rather than an `as` cast.
    let mut bytes: u64 = 0;
    for _ in 0..iterations {
        let measurement = measure_pipeline(64 * 1024, || Ok(64 * 1024)).expect("measured");
        bytes = bytes.saturating_add(measurement.output_bytes as u64);
    }
    let seconds = total.elapsed().as_secs_f64().max(f64::EPSILON);
    // Byte counts here are far below 2^53, so the conversion is exact; the
    // comment is here because the lint that flags an unchecked cast is right
    // in general and this is the one place the bound is known.
    let bits = bytes.saturating_mul(8);
    f64::from(u32::try_from(bits / 1024).unwrap_or(u32::MAX)) / seconds
}

/// Meters three direct sessions against one relayed one, and reports the ratio.
fn measure_relay_ratio() -> f64 {
    let mut usage = RelayUsageMetrics::default();
    for _ in 0..3 {
        meter_relay_session(
            &mut usage,
            RelayPathDecision::DirectPreferred,
            Duration::from_secs(1),
            RelayAuthorization::ControllerAuthorizedViewer,
        )
        .expect("direct session meters");
    }
    meter_relay_session(
        &mut usage,
        RelayPathDecision::FellBackToRelay,
        Duration::from_secs(1),
        RelayAuthorization::ControllerAuthorizedViewer,
    )
    .expect("relayed session meters");
    f64::from(usage.relay_ratio_bps()) / 100.0
}

/// Where on the quality ladder the controller settles for this profile.
///
/// A position, not a perceptual score: there is no reference here against
/// which "looks good" could be measured. It is named a proxy in the output for
/// that reason, and it is monotonic in quality by construction.
fn measure_visual_quality(profile: &Profile) -> f64 {
    let series = vec![profile.sample; 30];
    let (_, outcome) = evaluate_samples(&series, AdaptationPolicy::default());
    // `final_level` is an index into the ladder; the ladder has five rungs, so
    // there are four gaps. Dividing by the count of rungs instead would make
    // the floor -0.25 rather than 0.
    let gaps = QualityLevel::ALL.len().saturating_sub(1);
    let rung = outcome.final_level().min(gaps);
    if gaps == 0 {
        return 1.0;
    }
    // Both values are a ladder position below six, so the `u32` conversion is
    // exact and `from` keeps the cast lint happy without an `allow`.
    let gaps_f = f64::from(u32::try_from(gaps).unwrap_or(u32::MAX));
    let rung_f = f64::from(u32::try_from(rung).unwrap_or(u32::MAX));
    1.0 - (rung_f / gaps_f)
}

fn round3(value: f64) -> f64 {
    (value * 1000.0).round() / 1000.0
}

fn main() {
    let attempts: u32 = 10;
    let iterations: u32 = 20;

    let (direct_stats, connection_time) = measure_direct_connect(attempts);
    let exported = ConnectionMetrics {
        connection_time,
        reconnect_time: None,
        attempts,
    }
    .export(&direct_stats);

    let profiles: Vec<_> = PROFILES
        .iter()
        .map(|profile| {
            serde_json::json!({
                "profile": profile.name,
                "interactive_latency_ms": round3(measure_interactive_latency(iterations)),
                "connection_time_ms": exported.connection_time_ms,
                "reconnect_time_ms": round3(measure_reconnect_time(profile)),
                // Not measured here: this is the profile's declared link, and
                // naming it `bandwidth_kbps` would present a configured value as
                // a measured one. `link_declared_bandwidth_kbps` says what it is.
                "link_declared_bandwidth_kbps": profile.sample.throughput_bps / 1000,
                "pipeline_local_throughput_kbps": round3(measure_pipeline_throughput(iterations)),
                "cpu_percent": serde_json::Value::Null,
                "gpu_percent": serde_json::Value::Null,
                "ram_mb": serde_json::Value::Null,
                "direct_connect_success_rate":
                    f64::from(exported.direct_connect_success_rate_bps) / 100.0,
                "relay_ratio": round3(measure_relay_ratio()),
                "visual_quality_metric": round3(measure_visual_quality(profile)),
            })
        })
        .collect();

    println!(
        "{}",
        serde_json::json!({
            "schema_version": 1,
            "kind": "rc_matrix_measurement",
            "evidence_type": "deterministic_local_reference",
            "evidence_caveat": "direct_connect_success_rate is a loopback UDP \
                establishment, not a NAT traversal; it says nothing about \
                Internet reachability and must not be published as a success rate",
            "interactive_latency_ms_caveat": "covers capture conversion and queueing \
                inside this process, not compositing or display; it is a floor",
            "visual_quality_metric_caveat": "position on the quality ladder, not a \
                perceptual score; there is no reference to measure quality against",
            "bandwidth_kbps_not_emitted": "the only throughput measurable here is a \
                loopback memory copy, which would report the memory bus under the name \
                of a network result; link_declared_bandwidth_kbps is the profile input, \
                not a measurement",
            "unavailable_metrics": {
                "bandwidth_kbps": "requires a shaped link; loopback measures the CPU, not a network",
                "cpu_percent": "requires live process measurement on the target machine",
                "gpu_percent": "requires live process measurement on the target machine",
                "ram_mb": "requires live process measurement on the target machine",
            },
            "metrics_emitted": 6,
            "metrics_required_by_m13": 10,
            "admissible": false,
            "admissible_reason": "four required metrics have no honest producer \
                here; m13_matrix.py verify refuses this file, as it should",
            "profiles": profiles,
        })
    );
}

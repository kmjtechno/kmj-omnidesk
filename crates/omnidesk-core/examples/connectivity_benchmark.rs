use std::{
    net::UdpSocket,
    thread,
    time::Duration,
};

use omnidesk_core::{
    connectivity::DirectConnectStats,
    direct_udp::DirectProbe,
};
use omnidesk_protocol::signaling::{CandidateKind, ConnectionCandidate, TransportProtocol};

const ITERATIONS: u8 = 10;
const PROBE_BYTES: usize = 54;

fn main() {
    let peer = UdpSocket::bind("127.0.0.1:0").expect("bind benchmark peer");
    peer.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("peer timeout");
    let address = peer.local_addr().expect("peer address");

    let responder = thread::spawn(move || {
        for _ in 0..usize::from(ITERATIONS) * 2 {
            let mut request = [0_u8; PROBE_BYTES];
            let (received, source) = peer.recv_from(&mut request).expect("receive benchmark probe");
            assert_eq!(received, PROBE_BYTES);
            peer.send_to(&request, source).expect("echo benchmark probe");
        }
    });

    let candidate = ConnectionCandidate {
        kind: CandidateKind::Host,
        transport: TransportProtocol::Udp,
        address,
        priority: 100,
    };
    let probe = DirectProbe::new(Duration::from_secs(2));
    let mut stats = DirectConnectStats::default();
    let mut connect_micros = 0_u128;
    let mut reconnect_micros = 0_u128;

    for iteration in 0..ITERATIONS {
        let result = probe.connect_then_reconnect(
            &candidate,
            [1_u8; 16],
            [iteration; 32],
            [iteration.wrapping_add(1); 32],
        );
        match result {
            Ok(result) => {
                stats.record(true);
                connect_micros += result.metrics.connection_time.as_micros();
                reconnect_micros += result
                    .metrics
                    .reconnect_time
                    .expect("reconnect metric")
                    .as_micros();
            }
            Err(_) => stats.record(false),
        }
    }

    responder.join().expect("benchmark responder");
    let successes = u128::from(stats.successes()).max(1);
    println!(
        "{{\"schema_version\":1,\"kind\":\"local_udp_direct_reference\",\"iterations\":{},\"successes\":{},\"success_rate_bps\":{},\"avg_connection_us\":{},\"avg_reconnect_us\":{}}}",
        stats.attempts(),
        stats.successes(),
        stats.success_rate_bps(),
        connect_micros / successes,
        reconnect_micros / successes
    );
}

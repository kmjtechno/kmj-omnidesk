use std::{
    net::{SocketAddr, UdpSocket},
    thread,
    time::Duration,
};

use omnidesk_core::{
    direct_udp::DirectProbe,
    nat_traversal::{MappingBehavior, observe_mapping},
    reconnect::{ReconnectPolicy, ThreadSleeper, reconnect_direct},
    stun::StunClient,
};
use omnidesk_protocol::signaling::{CandidateKind, ConnectionCandidate, TransportProtocol};

const MAGIC_COOKIE: u32 = 0x2112_A442;
const XOR_MAPPED_ADDRESS: u16 = 0x0020;
const BINDING_SUCCESS: u16 = 0x0101;
const STUN_HEADER_BYTES: usize = 20;
const DIRECT_PROBE_BYTES: usize = 54;

fn stun_response(transaction_id: [u8; 12], mapped: SocketAddr) -> Vec<u8> {
    let SocketAddr::V4(mapped) = mapped else {
        panic!("matrix uses IPv4");
    };
    let cookie = MAGIC_COOKIE.to_be_bytes();
    let xor_port = mapped.port() ^ u16::from_be_bytes([cookie[0], cookie[1]]);
    let ip = mapped.ip().octets();

    let mut attribute = vec![0_u8; 12];
    attribute[0..2].copy_from_slice(&XOR_MAPPED_ADDRESS.to_be_bytes());
    attribute[2..4].copy_from_slice(&8_u16.to_be_bytes());
    attribute[4] = 0;
    attribute[5] = 0x01;
    attribute[6..8].copy_from_slice(&xor_port.to_be_bytes());
    for index in 0..4 {
        attribute[8 + index] = ip[index] ^ cookie[index];
    }

    let mut response = vec![0_u8; STUN_HEADER_BYTES];
    response[0..2].copy_from_slice(&BINDING_SUCCESS.to_be_bytes());
    response[2..4].copy_from_slice(
        &u16::try_from(attribute.len())
            .expect("attribute length")
            .to_be_bytes(),
    );
    response[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    response[8..20].copy_from_slice(&transaction_id);
    response.extend_from_slice(&attribute);
    response
}

fn spawn_stun(mapped: SocketAddr, transaction_id: [u8; 12]) -> (SocketAddr, thread::JoinHandle<()>) {
    let server = UdpSocket::bind("127.0.0.1:0").expect("bind STUN");
    let address = server.local_addr().expect("STUN address");
    let handle = thread::spawn(move || {
        let mut request = [0_u8; STUN_HEADER_BYTES];
        let (received, source) = server.recv_from(&mut request).expect("STUN request");
        assert_eq!(received, STUN_HEADER_BYTES);
        assert_eq!(&request[8..20], &transaction_id);
        server
            .send_to(&stun_response(transaction_id, mapped), source)
            .expect("STUN response");
    });
    (address, handle)
}

fn observe_case(first: SocketAddr, second: SocketAddr) -> MappingBehavior {
    let first_tx = [1_u8; 12];
    let second_tx = [2_u8; 12];
    let (first_server, first_thread) = spawn_stun(first, first_tx);
    let (second_server, second_thread) = spawn_stun(second, second_tx);
    let client = StunClient::new(Duration::from_secs(1));

    let observation = observe_mapping(
        &client,
        first_server,
        second_server,
        first_tx,
        second_tx,
    )
    .expect("mapping observation");
    first_thread.join().expect("first STUN");
    second_thread.join().expect("second STUN");
    observation.behavior
}

fn main() {
    let stable: SocketAddr = "203.0.113.10:50000".parse().expect("stable");
    let changed: SocketAddr = "203.0.113.10:50001".parse().expect("changed");
    let independent = observe_case(stable, stable);
    let dependent = observe_case(stable, changed);
    assert_eq!(independent, MappingBehavior::EndpointIndependentObserved);
    assert_eq!(dependent, MappingBehavior::EndpointDependentObserved);

    let peer = UdpSocket::bind("127.0.0.1:0").expect("bind peer");
    peer.set_read_timeout(Some(Duration::from_secs(2)))
        .expect("peer timeout");
    let peer_address = peer.local_addr().expect("peer address");
    let responder = thread::spawn(move || {
        for attempt in 1..=2 {
            let mut request = [0_u8; DIRECT_PROBE_BYTES];
            let (received, source) = peer.recv_from(&mut request).expect("direct probe");
            assert_eq!(received, DIRECT_PROBE_BYTES);
            if attempt == 2 {
                peer.send_to(&request, source).expect("direct echo");
            }
        }
    });

    let candidate = ConnectionCandidate {
        kind: CandidateKind::ServerReflexive,
        transport: TransportProtocol::Udp,
        address: peer_address,
        priority: 200,
    };
    let probe = DirectProbe::new(Duration::from_millis(40));
    let policy = ReconnectPolicy {
        max_rounds: 3,
        initial_backoff: Duration::from_millis(5),
        max_backoff: Duration::from_millis(20),
    };
    let result = reconnect_direct(
        &probe,
        &ThreadSleeper,
        policy,
        &[candidate],
        [7_u8; 16],
        &[[11_u8; 32], [12_u8; 32], [13_u8; 32]],
    )
    .expect("second reconnect round");
    responder.join().expect("direct responder");

    println!(
        "{{\"schema_version\":1,\"kind\":\"local_nat_reconnect_matrix\",\"same_socket_endpoint_independent_observed\":true,\"same_socket_endpoint_dependent_observed\":true,\"reconnect_rounds\":{},\"candidate_attempts\":{},\"reconnect_time_ms\":{}}}",
        result.rounds,
        result.candidate_attempts,
        result.reconnect_time.as_millis()
    );
}

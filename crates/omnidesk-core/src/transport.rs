use std::{
    collections::VecDeque,
    io::{ErrorKind, Read, Write},
    net::{Shutdown, SocketAddr, TcpStream},
    time::Duration,
};

const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathKind {
    Loopback,
    Lan,
    Direct,
    Relay,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportError {
    EmptyPayload,
    PayloadTooLarge,
    Closed,
    Io(ErrorKind),
}

pub trait Transport {
    /// Returns the currently selected transport path.
    fn path_kind(&self) -> PathKind;
    /// Sends one bounded transport payload.
    ///
    /// # Errors
    ///
    /// Returns an error when the transport is closed or the payload is invalid.
    fn send(&mut self, payload: &[u8]) -> Result<(), TransportError>;
    /// Receives one complete transport payload when available.
    ///
    /// # Errors
    ///
    /// Returns an error when the transport is closed or an invalid frame/I/O failure occurs.
    fn receive(&mut self) -> Result<Option<Vec<u8>>, TransportError>;
    /// Closes the transport and discards any queued local payloads.
    fn close(&mut self);
}

#[derive(Debug, Default)]
pub struct LoopbackTransport {
    queue: VecDeque<Vec<u8>>,
    closed: bool,
}

impl Transport for LoopbackTransport {
    fn path_kind(&self) -> PathKind {
        PathKind::Loopback
    }

    fn send(&mut self, payload: &[u8]) -> Result<(), TransportError> {
        if self.closed {
            return Err(TransportError::Closed);
        }
        if payload.is_empty() {
            return Err(TransportError::EmptyPayload);
        }

        self.queue.push_back(payload.to_vec());
        Ok(())
    }

    fn receive(&mut self) -> Result<Option<Vec<u8>>, TransportError> {
        if self.closed {
            return Err(TransportError::Closed);
        }

        Ok(self.queue.pop_front())
    }

    fn close(&mut self) {
        self.queue.clear();
        self.closed = true;
    }
}

/// Length-delimited TCP transport used for the first measurable LAN path.
///
/// This transport deliberately provides framing and bounded allocation only.
/// Authentication and control authorization remain session-layer requirements;
/// callers must not treat a successful TCP connection as authorization.
#[derive(Debug)]
pub struct TcpLanTransport {
    stream: TcpStream,
    closed: bool,
}

impl TcpLanTransport {
    /// Opens a bounded-time TCP LAN connection.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the peer cannot be connected or configured.
    pub fn connect(address: SocketAddr, timeout: Duration) -> Result<Self, TransportError> {
        let stream =
            TcpStream::connect_timeout(&address, timeout).map_err(|error| io_error(&error))?;
        Self::from_stream(stream)
    }

    /// Wraps an established TCP stream as a LAN transport.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when low-latency stream configuration fails.
    pub fn from_stream(stream: TcpStream) -> Result<Self, TransportError> {
        stream.set_nodelay(true).map_err(|error| io_error(&error))?;
        Ok(Self {
            stream,
            closed: false,
        })
    }

    const fn ensure_open(&self) -> Result<(), TransportError> {
        if self.closed {
            Err(TransportError::Closed)
        } else {
            Ok(())
        }
    }
}

impl Transport for TcpLanTransport {
    fn path_kind(&self) -> PathKind {
        PathKind::Lan
    }

    fn send(&mut self, payload: &[u8]) -> Result<(), TransportError> {
        self.ensure_open()?;

        if payload.is_empty() {
            return Err(TransportError::EmptyPayload);
        }
        if payload.len() > MAX_FRAME_BYTES {
            return Err(TransportError::PayloadTooLarge);
        }

        let length = u32::try_from(payload.len()).map_err(|_| TransportError::PayloadTooLarge)?;
        self.stream
            .write_all(&length.to_be_bytes())
            .map_err(|error| io_error(&error))?;
        self.stream
            .write_all(payload)
            .map_err(|error| io_error(&error))?;
        self.stream.flush().map_err(|error| io_error(&error))
    }

    fn receive(&mut self) -> Result<Option<Vec<u8>>, TransportError> {
        self.ensure_open()?;

        let mut header = [0_u8; 4];
        if let Err(error) = self.stream.read_exact(&mut header) {
            if error.kind() == ErrorKind::UnexpectedEof {
                self.closed = true;
                return Err(TransportError::Closed);
            }
            return Err(io_error(&error));
        }

        let length = usize::try_from(u32::from_be_bytes(header))
            .map_err(|_| TransportError::PayloadTooLarge)?;
        if length == 0 {
            return Err(TransportError::EmptyPayload);
        }
        if length > MAX_FRAME_BYTES {
            return Err(TransportError::PayloadTooLarge);
        }

        let mut payload = vec![0_u8; length];
        self.stream
            .read_exact(&mut payload)
            .map_err(|error| io_error(&error))?;
        Ok(Some(payload))
    }

    fn close(&mut self) {
        if !self.closed {
            let _ = self.stream.shutdown(Shutdown::Both);
            self.closed = true;
        }
    }
}

fn io_error(error: &std::io::Error) -> TransportError {
    TransportError::Io(error.kind())
}

#[cfg(test)]
mod tests {
    use std::{net::TcpListener, thread, time::Duration};

    use super::*;

    #[test]
    fn loopback_preserves_payload_order() {
        let mut transport = LoopbackTransport::default();
        transport.send(b"one").expect("send one");
        transport.send(b"two").expect("send two");

        assert_eq!(transport.receive().expect("receive"), Some(b"one".to_vec()));
        assert_eq!(transport.receive().expect("receive"), Some(b"two".to_vec()));
        assert_eq!(transport.receive().expect("receive"), None);
    }

    #[test]
    fn closed_transport_fails_closed_and_drops_queue() {
        let mut transport = LoopbackTransport::default();
        transport.send(b"sensitive").expect("send");
        transport.close();

        assert_eq!(transport.send(b"late"), Err(TransportError::Closed));
        assert_eq!(transport.receive(), Err(TransportError::Closed));
    }

    #[test]
    fn empty_payload_is_rejected() {
        let mut transport = LoopbackTransport::default();
        assert_eq!(transport.send(&[]), Err(TransportError::EmptyPayload));
    }

    #[test]
    fn tcp_lan_transport_round_trips_framed_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind LAN proof listener");
        let address = listener.local_addr().expect("listener address");

        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept LAN proof client");
            let mut transport = TcpLanTransport::from_stream(stream).expect("server transport");

            assert_eq!(transport.path_kind(), PathKind::Lan);
            assert_eq!(
                transport.receive().expect("receive ping"),
                Some(b"ping".to_vec())
            );
            transport.send(b"pong").expect("send pong");
        });

        let mut client =
            TcpLanTransport::connect(address, Duration::from_secs(2)).expect("client transport");
        assert_eq!(client.path_kind(), PathKind::Lan);
        client.send(b"ping").expect("send ping");
        assert_eq!(
            client.receive().expect("receive pong"),
            Some(b"pong".to_vec())
        );
        client.close();
        assert_eq!(client.send(b"late"), Err(TransportError::Closed));

        server.join().expect("LAN proof server");
    }

    #[test]
    fn tcp_lan_transport_rejects_oversized_frame_before_write() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let address = listener.local_addr().expect("listener address");

        let server = thread::spawn(move || listener.accept().expect("accept").0);
        let mut client =
            TcpLanTransport::connect(address, Duration::from_secs(2)).expect("client transport");
        let _server_stream = server.join().expect("server stream");

        let oversized = vec![0_u8; MAX_FRAME_BYTES + 1];
        assert_eq!(
            client.send(&oversized),
            Err(TransportError::PayloadTooLarge)
        );
    }
}

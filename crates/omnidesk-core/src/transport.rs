use std::collections::VecDeque;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathKind {
    Loopback,
    Lan,
    Direct,
    Relay,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    EmptyPayload,
    Closed,
}

pub trait Transport {
    fn path_kind(&self) -> PathKind;
    fn send(&mut self, payload: &[u8]) -> Result<(), TransportError>;
    fn receive(&mut self) -> Result<Option<Vec<u8>>, TransportError>;
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

#[cfg(test)]
mod tests {
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
}

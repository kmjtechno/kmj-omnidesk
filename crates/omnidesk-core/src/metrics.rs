#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SessionMetrics {
    sent_bytes: u64,
    received_bytes: u64,
    sent_frames: u64,
    received_frames: u64,
    reconnects: u64,
}

impl SessionMetrics {
    pub fn record_sent(&mut self, bytes: usize) {
        self.sent_bytes = self.sent_bytes.saturating_add(bytes as u64);
    }

    pub fn record_received(&mut self, bytes: usize) {
        self.received_bytes = self.received_bytes.saturating_add(bytes as u64);
    }

    pub fn record_sent_frame(&mut self) {
        self.sent_frames = self.sent_frames.saturating_add(1);
    }

    pub fn record_received_frame(&mut self) {
        self.received_frames = self.received_frames.saturating_add(1);
    }

    pub fn record_reconnect(&mut self) {
        self.reconnects = self.reconnects.saturating_add(1);
    }

    #[must_use]
    pub fn sent_bytes(&self) -> u64 {
        self.sent_bytes
    }

    #[must_use]
    pub fn received_bytes(&self) -> u64 {
        self.received_bytes
    }

    #[must_use]
    pub fn sent_frames(&self) -> u64 {
        self.sent_frames
    }

    #[must_use]
    pub fn received_frames(&self) -> u64 {
        self.received_frames
    }

    #[must_use]
    pub fn reconnects(&self) -> u64 {
        self.reconnects
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_are_monotonic() {
        let mut metrics = SessionMetrics::default();

        metrics.record_sent(100);
        metrics.record_sent(50);
        metrics.record_received(80);
        metrics.record_sent_frame();
        metrics.record_received_frame();
        metrics.record_reconnect();

        assert_eq!(metrics.sent_bytes(), 150);
        assert_eq!(metrics.received_bytes(), 80);
        assert_eq!(metrics.sent_frames(), 1);
        assert_eq!(metrics.received_frames(), 1);
        assert_eq!(metrics.reconnects(), 1);
    }
}

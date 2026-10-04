//! Bounded frame queue between capture and transport.
//!
//! M2's `no_unbounded_frame_queue` was the one exit criterion in that
//! milestone with no code behind it: `pipeline.rs` runs one bounded
//! capture-to-render cycle at a time, so the queue a real streaming session
//! needs between a fast capture and a slow network did not exist. The criterion
//! was satisfied by the sentence declaring it.
//!
//! The failure it names is concrete and does not need the queue to be used
//! before it happens. If a sender can outrun a network, an unbounded buffer
//! grows until the process is killed -- and the video does not merely stutter,
//! it stops, because the process that would have recovered is the one that ran
//! out of memory. The user sees a frozen screen. On a remote desktop that is
//! indistinguishable from a crashed host.
//!
//! So the bound is a property of the type, not a convention callers remember:
//! [`FrameQueue`] has no method that can make it exceed `capacity`, and
//! [`FrameQueue::push`] reports rather than grows when it is full.
//!
//! ## What happens when the queue is full
//!
//! A remote desktop is not a video file. A frame that arrives after the network
//! fell behind is stale by definition: the user has already moved on, and
//! delivering it makes the image jump backwards. Dropping the newest frame and
//! keeping the queued ones preserves the most recent coherent state, which is
//! what the user actually wants. This is why the overflow error is
//! [`FrameQueueError::Full`] and not [`FrameQueueError::Full`] with the old
//! frames discarded -- see [`FrameQueue::push`] for the policy and why
//! dropping-oldest is the alternative that was rejected.

use std::collections::VecDeque;

use crate::media::EncodedFrame;

/// Largest number of frames a single queue will hold.
///
/// A hard ceiling on the queue depth, and through it on queued bytes once
/// frames are bounded in size. Twelve frames at a typical inter-frame interval
/// is a quarter-second of backlog: long enough to ride out a brief stall,
/// short enough that the process cannot be killed by a network that stays
/// slow. The value is a policy, not a derivation, and the queue refuses to
/// exceed whatever capacity it is given.
pub const DEFAULT_FRAME_QUEUE_CAPACITY: usize = 12;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameQueueError {
    /// The queue already holds `capacity` frames.
    ///
    /// Carries the capacity so a caller can size its own buffer rather than
    /// hard-code this one, and so the refusal says what the limit was instead
    /// of only that something was exceeded.
    Full { capacity: usize },
}

impl core::fmt::Display for FrameQueueError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Full { capacity } => {
                write!(formatter, "frame queue is full at {capacity} frames")
            }
        }
    }
}

impl std::error::Error for FrameQueueError {}

/// A fixed-capacity queue of encoded frames awaiting transport.
///
/// The capacity is fixed at construction and cannot be changed afterwards. That
/// is the point: a queue whose capacity can grow under pressure is unbounded
/// by another name, and `VecDeque::with_capacity` is not a bound -- it is a
/// hint, and the collection grows past it freely.
#[derive(Debug)]
pub struct FrameQueue {
    frames: VecDeque<EncodedFrame>,
    capacity: usize,
    dropped: u64,
}

impl FrameQueue {
    /// Creates a queue holding at most `capacity` frames.
    ///
    /// A capacity of zero is refused by every `push` rather than accepted and
    /// ignored, so a misconfigured caller learns immediately instead of
    /// silently queueing nothing and concluding the network is dropping
    /// frames.
    #[must_use]
    pub const fn with_capacity(capacity: usize) -> Self {
        // `VecDeque::with_capacity` is a starting allocation, not a limit, so
        // the limit is enforced by `push` against this field. Pre-allocating
        // the full capacity would let a caller who chose badly allocate the
        // whole thing up front, which is its own denial-of-service.
        Self {
            frames: VecDeque::new(),
            capacity,
            dropped: 0,
        }
    }

    /// Creates a queue at [`DEFAULT_FRAME_QUEUE_CAPACITY`].
    #[must_use]
    pub const fn new() -> Self {
        Self::with_capacity(DEFAULT_FRAME_QUEUE_CAPACITY)
    }

    /// Appends a frame, or reports that the queue is full.
    ///
    /// # Errors
    ///
    /// Returns [`FrameQueueError::Full`] when the queue is at capacity. The
    /// frame is *not* queued and the queue is *not* grown, and the dropped
    /// counter advances.
    ///
    /// ## Why the newest frame is the one refused
    ///
    /// Dropping the oldest queued frame instead would keep this one and
    /// discard a frame the network had not yet managed to send -- but the
    /// queued frames are the ones already ordered for transmission. Dropping
    /// from the front reorders nothing, yet it deletes the oldest still-current
    /// view in favour of a newest one that then queues behind everything.
    ///
    /// The simpler argument is the one that matters to the user: when the
    /// network falls behind, the frames sitting in the queue are the frames
    /// the user has not yet seen, and they are still in order. The frame
    /// arriving now is the newest view, and if it cannot be sent promptly it
    /// will be stale before it arrives anyway. Refusing it loses one frame.
    /// Dropping-oldest loses one frame too -- and keeps a queue whose head is
    /// older than the frame that just failed to fit, which is the ordering a
    /// user notices as the image stuttering backwards.
    pub fn push(&mut self, frame: EncodedFrame) -> Result<(), FrameQueueError> {
        if self.frames.len() >= self.capacity {
            self.dropped = self.dropped.saturating_add(1);
            return Err(FrameQueueError::Full {
                capacity: self.capacity,
            });
        }
        self.frames.push_back(frame);
        Ok(())
    }

    /// Removes and returns the oldest frame.
    #[must_use]
    pub fn pop(&mut self) -> Option<EncodedFrame> {
        self.frames.pop_front()
    }

    /// Returns the queued frames, oldest first, without removing them.
    ///
    /// No `#[must_use]` here: `impl Iterator` is already must-use, and
    /// clippy rejects the attribute as redundant rather than as harmless.
    pub fn peek(&self) -> impl Iterator<Item = &EncodedFrame> {
        self.frames.iter()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.frames.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }

    /// The ceiling this queue was built with. Cannot be exceeded.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Number of frames refused for want of room.
    ///
    /// Exposed because a queue that silently drops is worse than one that
    /// does not: a caller with no visibility into drops concludes the network
    /// is at fault. This is the number that distinguishes the two.
    #[must_use]
    pub const fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Bytes currently held across all queued frames.
    #[must_use]
    pub fn queued_bytes(&self) -> usize {
        self.frames.iter().map(|frame| frame.payload.len()).sum()
    }
}

impl Default for FrameQueue {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{DEFAULT_FRAME_QUEUE_CAPACITY, FrameQueue, FrameQueueError};

    fn frame(byte: u8) -> EncodedFrame {
        EncodedFrame {
            payload: vec![byte; 4],
            regions: Vec::new(),
        }
    }

    /// Mutation: change `>=` to `>` in the fullness check.
    ///
    /// With `>` the queue holds one frame more than its stated capacity, so
    /// the bound this module exists to enforce is off by exactly the size of
    /// the thing it was added for. The test asserts the queue is full at
    /// *exactly* `capacity`, which is where `>` and `>=` disagree.
    #[test]
    fn the_queue_refuses_at_exactly_its_capacity() {
        let mut queue = FrameQueue::with_capacity(3);
        for index in 0..3 {
            queue.push(frame(index)).expect("within capacity");
        }
        assert_eq!(queue.len(), 3);
        assert_eq!(
            queue.push(frame(99)),
            Err(FrameQueueError::Full { capacity: 3 }),
            "the fourth push must be refused at a capacity of three",
        );
        assert_eq!(queue.len(), 3, "a refused push must not grow the queue");
    }

    /// Mutation: delete the `return Err(...)` and grow instead.
    ///
    /// The whole point of the type. If this is removed the queue is unbounded
    /// and the milestone criterion it satisfies is a claim about code that no
    /// longer does anything.
    #[test]
    fn a_full_queue_never_grows() {
        let mut queue = FrameQueue::with_capacity(2);
        queue.push(frame(1)).unwrap();
        queue.push(frame(2)).unwrap();
        for _ in 0..1000 {
            let _ = queue.push(frame(3));
        }
        assert_eq!(queue.len(), 2);
        assert_eq!(queue.dropped(), 1000);
    }

    /// Mutation: drop the `dropped` counter increment.
    ///
    /// A queue that silently discards is worse than one that does not: with
    /// no counter, a caller whose frames are vanishing concludes the network
    /// is at fault and debugs the wrong thing.
    #[test]
    fn dropped_frames_are_counted() {
        let mut queue = FrameQueue::with_capacity(1);
        queue.push(frame(1)).unwrap();
        let _ = queue.push(frame(2));
        let _ = queue.push(frame(3));
        assert_eq!(queue.dropped(), 2);
    }

    /// Mutation: `saturating_add` -> `+=` is not the risk here; the risk is
    /// removing the counter entirely. Asserted through `u64::MAX` so a wrap
    /// cannot silently pass for a large count.
    #[test]
    fn the_dropped_counter_saturates_rather_than_wrapping() {
        let mut queue = FrameQueue::with_capacity(1);
        queue.push(frame(1)).unwrap();
        queue.dropped = u64::MAX - 1;
        let _ = queue.push(frame(2));
        let _ = queue.push(frame(3));
        assert_eq!(
            queue.dropped(),
            u64::MAX,
            "counting must saturate, not wrap"
        );
    }

    /// Mutation: `pop_front` -> `pop_back`.
    ///
    /// A queue drained newest-first delivers frames out of order, which on a
    /// remote desktop is the image stuttering backwards. This is the check
    /// that pins *order*, which a length assertion would not.
    #[test]
    fn frames_come_out_oldest_first() {
        let mut queue = FrameQueue::with_capacity(4);
        for index in [1u8, 2, 3] {
            queue.push(frame(index)).unwrap();
        }
        let mut order = Vec::new();
        while let Some(out) = queue.pop() {
            order.push(out.payload[0]);
        }
        assert_eq!(order, vec![1, 2, 3]);
    }

    /// Mutation: make `peek` consume, or return in the wrong order.
    #[test]
    fn peeking_does_not_remove_anything() {
        let mut queue = FrameQueue::with_capacity(4);
        queue.push(frame(1)).unwrap();
        assert_eq!(queue.peek().count(), 1);
        assert_eq!(queue.len(), 1, "peek must not consume");
        assert_eq!(queue.peek().next().map(|f| f.payload[0]), Some(1));
        assert_eq!(queue.len(), 1);
    }

    /// Mutation: delete the capacity field and use `VecDeque`'s own capacity.
    ///
    /// `VecDeque::with_capacity` is a starting allocation, not a limit. A queue
    /// that relies on it is unbounded, and the only thing that would catch
    /// that is the module refusing to grow past its stated ceiling.
    #[test]
    fn the_capacity_cannot_be_changed_after_construction() {
        let mut queue = FrameQueue::with_capacity(2);
        assert_eq!(queue.capacity(), 2);
        for index in 0..50 {
            let _ = queue.push(frame(index));
        }
        assert_eq!(queue.capacity(), 2, "capacity is fixed at construction");
    }

    #[test]
    fn a_zero_capacity_queue_refuses_everything_rather_than_silently_accepting() {
        let mut queue = FrameQueue::with_capacity(0);
        assert_eq!(
            queue.push(frame(1)),
            Err(FrameQueueError::Full { capacity: 0 })
        );
        assert!(queue.is_empty());
    }

    /// Mutation: `capacity()` returning `len()` instead.
    #[test]
    fn capacity_is_the_ceiling_not_the_current_depth() {
        let mut queue = FrameQueue::with_capacity(5);
        queue.push(frame(1)).unwrap();
        assert_eq!(queue.capacity(), 5);
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn the_default_queue_has_the_documented_capacity() {
        let queue = FrameQueue::new();
        assert_eq!(queue.capacity(), DEFAULT_FRAME_QUEUE_CAPACITY);
    }

    /// Mutation: drop the `default()` body / make `new()` unbounded.
    #[test]
    fn default_and_new_agree() {
        let mut a = FrameQueue::default();
        let mut b = FrameQueue::new();
        assert_eq!(a.capacity(), b.capacity());
        for _ in 0..DEFAULT_FRAME_QUEUE_CAPACITY {
            a.push(frame(1)).unwrap();
            b.push(frame(1)).unwrap();
        }
        assert!(a.push(frame(2)).is_err());
        assert!(b.push(frame(2)).is_err());
    }

    /// Mutation: `queued_bytes` summing only the first frame.
    #[test]
    fn queued_bytes_sums_every_queued_frame() {
        let mut queue = FrameQueue::with_capacity(4);
        queue.push(frame(1)).unwrap();
        queue.push(frame(2)).unwrap();
        queue.push(frame(3)).unwrap();
        assert_eq!(queue.queued_bytes(), 12);
    }

    /// Mutation: pop from an empty queue returning something.
    #[test]
    fn popping_an_empty_queue_yields_nothing() {
        let mut queue = FrameQueue::with_capacity(2);
        assert!(queue.pop().is_none());
        queue.push(frame(1)).unwrap();
        assert!(queue.pop().is_some());
        assert!(queue.pop().is_none());
    }

    use crate::media::EncodedFrame;
}

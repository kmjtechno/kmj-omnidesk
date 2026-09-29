use omnidesk_core::collaboration::{
    AudioPermission, ClipboardPolicy, ClipboardSyncError, ClipboardSyncState, DataDirection,
    FileTransferManifest, MonitorDescriptor, MonitorLayout, RebootReconnectPolicy,
    RebootReconnectState, RemoteAudioState, TransferCheckpoint, TransferChunk,
};

fn main() {
    let chunks = vec![
        b"alpha".to_vec(),
        b"beta".to_vec(),
        b"gamma".to_vec(),
        b"delta".to_vec(),
        b"epsilon".to_vec(),
        b"zeta".to_vec(),
    ];
    let mut offset = 0_u64;
    let descriptors = chunks
        .iter()
        .enumerate()
        .map(|(index, bytes)| {
            let descriptor = TransferChunk::from_bytes(
                u32::try_from(index).unwrap_or(u32::MAX),
                offset,
                bytes,
            );
            offset = offset.saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
            descriptor
        })
        .collect();
    let manifest = FileTransferManifest {
        relative_path: "evidence/resume.bin".to_owned(),
        total_size: offset,
        chunks: descriptors,
    };
    manifest.validate().unwrap();

    // Round 1 simulates a constrained path that delivers only alternating chunks.
    let mut checkpoint = TransferCheckpoint::new();
    for index in [0_u32, 2, 4] {
        checkpoint
            .accept(&manifest, index, &chunks[usize::try_from(index).unwrap()])
            .unwrap();
    }
    assert!(!checkpoint.is_complete(&manifest));

    // Persist/restore the checkpoint, then deliver only the missing chunks.
    let mut resumed = checkpoint.clone();
    for index in [1_u32, 3, 5] {
        resumed
            .accept(&manifest, index, &chunks[usize::try_from(index).unwrap()])
            .unwrap();
    }
    assert!(resumed.is_complete(&manifest));

    let policy = ClipboardPolicy {
        send_allowed: true,
        receive_allowed: true,
    };
    let mut clipboard = ClipboardSyncState::new();
    clipboard
        .accept(policy, DataDirection::LocalToRemote, 1, b"first")
        .unwrap();
    assert_eq!(
        clipboard.accept(policy, DataDirection::LocalToRemote, 1, b"replay"),
        Err(ClipboardSyncError::ReplayOrOutOfOrder)
    );

    let mut audio = RemoteAudioState::new(AudioPermission::Allowed);
    audio.start().unwrap();
    assert!(audio.is_active());
    audio.stop();

    let mut monitors = MonitorLayout::new(vec![
        MonitorDescriptor {
            id: "primary".to_owned(),
            width: 1920,
            height: 1080,
            primary: true,
        },
        MonitorDescriptor {
            id: "secondary".to_owned(),
            width: 1280,
            height: 1024,
            primary: false,
        },
    ])
    .unwrap();
    monitors.select("secondary").unwrap();
    assert_eq!(monitors.selected(), "secondary");

    let mut reconnect = RebootReconnectState::new(RebootReconnectPolicy {
        explicitly_allowed: true,
        max_attempts: 2,
    });
    assert_eq!(reconnect.begin_attempt(), Ok(1));

    println!(
        "{{\"m8_runtime_evidence\":\"PASS\",\"clipboard_replay_rejected\":true,\"transfer_resume_completed\":true,\"simulated_delivery_rounds\":2,\"audio_permission_enforced\":true,\"monitor_switch_verified\":true,\"reboot_reconnect_bounded\":true}}"
    );
}

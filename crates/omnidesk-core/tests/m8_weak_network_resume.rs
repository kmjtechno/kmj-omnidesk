use omnidesk_core::collaboration::{
    FileTransferManifest, TransferCheckpoint, TransferChunk, TransferReceiveError,
};

fn manifest(parts: &[&[u8]]) -> FileTransferManifest {
    let mut offset = 0_u64;
    let chunks = parts
        .iter()
        .enumerate()
        .map(|(index, bytes)| {
            let chunk = TransferChunk::from_bytes(
                u32::try_from(index).expect("fixture index fits u32"),
                offset,
                bytes,
            );
            offset += u64::try_from(bytes.len()).expect("fixture length fits u64");
            chunk
        })
        .collect();

    FileTransferManifest {
        relative_path: "evidence/weak-network.bin".to_owned(),
        total_size: offset,
        chunks,
    }
}

#[test]
fn deterministic_weak_network_resume_recovers_without_accepting_corruption() {
    let payloads: Vec<&[u8]> = vec![
        b"frame-0000",
        b"frame-1111",
        b"frame-2222",
        b"frame-3333",
        b"frame-4444",
    ];
    let manifest = manifest(&payloads);
    manifest.validate().expect("fixture manifest must be valid");

    let mut checkpoint = TransferCheckpoint::new();
    let mut accepted = 0_u32;
    let mut simulated_drops = 0_u32;
    let mut rejected_corruptions = 0_u32;

    // Deterministic constrained-link pass: chunks 1 and 3 are dropped, while
    // chunk 2 arrives corrupted. Only integrity-verified bytes may advance state.
    for (index, payload) in payloads.iter().enumerate() {
        if matches!(index, 1 | 3) {
            simulated_drops += 1;
            continue;
        }
        if index == 2 {
            let mut corrupted = payload.to_vec();
            corrupted[0] ^= 0xff;
            assert_eq!(
                checkpoint.accept(&manifest, 2, &corrupted),
                Err(TransferReceiveError::ChunkIntegrityFailed)
            );
            rejected_corruptions += 1;
            continue;
        }
        checkpoint
            .accept(
                &manifest,
                u32::try_from(index).expect("fixture index fits u32"),
                payload,
            )
            .expect("intact chunk must be accepted");
        accepted += 1;
    }

    assert_eq!(simulated_drops, 2);
    assert_eq!(rejected_corruptions, 1);
    assert_eq!(accepted, 2);
    assert!(!checkpoint.is_complete(&manifest));
    assert_eq!(checkpoint.next_missing_chunk(&manifest), Some(1));

    // Simulate persistence across a disconnect, then resume strictly from the
    // checkpoint until all missing chunks are integrity-verified.
    let mut resumed = checkpoint.clone();
    let mut resumed_chunks = 0_u32;
    while let Some(index) = resumed.next_missing_chunk(&manifest) {
        let payload = payloads[usize::try_from(index).expect("fixture index fits usize")];
        resumed
            .accept(&manifest, index, payload)
            .expect("resumed intact chunk must be accepted");
        resumed_chunks += 1;
    }

    assert_eq!(resumed_chunks, 3);
    assert!(resumed.is_complete(&manifest));
    assert_eq!(
        resumed.completed_chunks().collect::<Vec<_>>(),
        vec![0, 1, 2, 3, 4]
    );
}

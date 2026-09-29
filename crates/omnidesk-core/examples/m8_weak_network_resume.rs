use omnidesk_core::collaboration::{
    FileTransferManifest, TransferCheckpoint, TransferChunk,
};

#[derive(Clone, Copy)]
struct Profile {
    name: &'static str,
    delivery_modulus: u32,
    max_rounds: u32,
}

fn build_manifest() -> (FileTransferManifest, Vec<Vec<u8>>) {
    let chunks = (0_u8..24)
        .map(|index| vec![index; 1024])
        .collect::<Vec<_>>();
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

    (
        FileTransferManifest {
            relative_path: "evidence/weak-network-resume.bin".to_owned(),
            total_size: offset,
            chunks: descriptors,
        },
        chunks,
    )
}

fn run_profile(profile: Profile) -> u32 {
    let (manifest, chunks) = build_manifest();
    manifest.validate().expect("fixture manifest must be valid");

    let mut checkpoint = TransferCheckpoint::new();

    for round in 0..profile.max_rounds {
        let missing = manifest
            .chunks
            .iter()
            .map(|chunk| chunk.index)
            .filter(|index| !checkpoint.completed_chunks().any(|done| done == *index))
            .collect::<Vec<_>>();

        if missing.is_empty() {
            return round;
        }

        for index in missing {
            let should_deliver =
                (index.saturating_add(round)) % profile.delivery_modulus == 0
                    || round + 1 == profile.max_rounds;
            if should_deliver {
                checkpoint
                    .accept(
                        &manifest,
                        index,
                        &chunks[usize::try_from(index).expect("fixture chunk index fits usize")],
                    )
                    .expect("fixture chunk must verify");
            }
        }

        if checkpoint.is_complete(&manifest) {
            return round + 1;
        }
    }

    panic!("profile {} did not complete within retry budget", profile.name);
}

fn main() {
    let profiles = [
        Profile {
            name: "office_good",
            delivery_modulus: 2,
            max_rounds: 3,
        },
        Profile {
            name: "mobile_constrained",
            delivery_modulus: 3,
            max_rounds: 5,
        },
        Profile {
            name: "weak_mobile",
            delivery_modulus: 4,
            max_rounds: 6,
        },
        Profile {
            name: "severe",
            delivery_modulus: 6,
            max_rounds: 8,
        },
    ];

    let mut results = Vec::new();
    for profile in profiles {
        let rounds = run_profile(profile);
        results.push(format!(
            "{{\"profile\":\"{}\",\"completed\":true,\"rounds\":{}}}",
            profile.name, rounds
        ));
    }

    println!(
        "{{\"m8_weak_network_resume\":\"PASS\",\"evidence_type\":\"deterministic_synthetic_impairment\",\"profiles\":[{}]}}",
        results.join(",")
    );
}

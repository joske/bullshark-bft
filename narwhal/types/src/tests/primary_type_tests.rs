// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::UnsignedHeader;
use crate::{BatchDigest, CertificateDigest, Header, HeaderDigest};
use config::WorkerId;
use crypto::{Digest, Hash, KeyPair};
use once_cell::sync::OnceCell;
use proptest::{collection, prelude::*, strategy::Strategy};
use rand::{rngs::StdRng, thread_rng, SeedableRng};

fn arb_keypair() -> impl Strategy<Value = KeyPair> {
    (any::<[u8; 32]>())
        .prop_map(|rand| {
            let mut rng = StdRng::from_seed(rand);
            KeyPair::new(&mut rng).unwrap()
        })
        .no_shrink()
}

fn clean_signed_header(kp: KeyPair) -> impl Strategy<Value = Header> {
    (
        any::<u64>(),
        any::<u64>(),
        collection::vec((BatchDigest::arbitrary(), any::<u32>()), 0..10),
        collection::vec(CertificateDigest::arbitrary(), 0..10),
    )
        .prop_map(move |(round, epoch, batches, parents)| {
            let payload = batches
                .into_iter()
                .map(|(batch_digest, worker_id)| (batch_digest, (worker_id as WorkerId, 0)))
                .collect();

            let parents = parents.into_iter().collect();

            let header = UnsignedHeader {
                author: kp.public().clone(),
                round,
                epoch,
                created_at: 0,
                payload,
                parents,
                digest: OnceCell::default(),
            };
            let digest = Hash::digest(&header);
            header.digest.set(digest).unwrap();
            let pk = &kp.private();
            let mut rng = thread_rng();
            let signature = pk
                .sign_bytes(Digest::from(digest).as_ref(), &mut rng)
                .unwrap();
            Header {
                author: header.author,
                round: header.round,
                epoch: header.epoch,
                created_at: header.created_at,
                payload: header.payload,
                parents: header.parents,
                digest: header.digest,
                signature,
            }
        })
}

fn arb_signed_header(kp: KeyPair) -> impl Strategy<Value = Header> {
    (
        clean_signed_header(kp.clone()),
        HeaderDigest::arbitrary(),
        any::<usize>(),
    )
        .prop_map(move |(clean_header, random_digest, naughtiness)| {
            let naughtiness = naughtiness % 100;
            if naughtiness < 95 {
                clean_header
            } else if naughtiness < 99 {
                let pk = &kp.private();
                let mut rng = thread_rng();
                let signature = pk
                    .sign_bytes(Digest::from(random_digest).as_ref(), &mut rng)
                    .unwrap();
                // naughty: we provide a well-signed random header
                Header {
                    digest: OnceCell::with_value(random_digest),
                    signature,
                    ..clean_header
                }
            } else {
                // naughty: we provide an ill-signed random header
                Header {
                    digest: OnceCell::with_value(random_digest),
                    ..clean_header
                }
            }
        })
}

fn arb_header() -> impl Strategy<Value = Header> {
    arb_keypair().prop_flat_map(arb_signed_header)
}

proptest! {
    #[test]
    fn header_deserializes_to_correct_id(header in arb_header()) {
        let serialized = bincode::serialize(&header).unwrap();
        let deserialized: Header = bincode::deserialize(&serialized).unwrap();
        // We may not have header.digest() == Hash::digest(header), due to the naughty cases above.
        //
        // Indeed, the naughty headers are specially crafted so that their `digest` is populated with a wrong digest.
        // They are malformed, since a correct header always has `foo.digest() == Hash::digest(foo)`.
        // We check here that deserializing a header, even a malformed one,
        // produces a correctly-formed header in all cases.
        assert_eq!(deserialized.digest(), Hash::digest(&header));
    }

}

// Copyright (c) 2021, Facebook, Inc. and its affiliates
// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::mutable_key_type)]

use crate::{ConsensusError, SequenceNumber};
use config::Committee;
use crypto::PublicKey;
use fastcrypto::hash::Hash;
use snarkos_metrics::{gauge, histogram};
use std::{
    cmp::{max, Ordering},
    collections::{BTreeMap, HashMap},
    sync::Arc,
};
use storage::CertificateStore;
use tokio::{
    sync::{mpsc, watch},
    task::JoinHandle,
};
use tracing::{debug, info, instrument};
use types::{
    Certificate, CertificateDigest, CommittedSubDag, ConditionalBroadcastReceiver, ConsensusStore,
    Round, StoreResult, Timestamp,
};

#[cfg(test)]
#[path = "tests/consensus_tests.rs"]
pub mod consensus_tests;

/// The representation of the DAG in memory.
pub type Dag = BTreeMap<Round, HashMap<PublicKey, (CertificateDigest, Certificate)>>;

/// The state that needs to be persisted for crash-recovery.
pub struct ConsensusState {
    /// The last committed round.
    pub last_committed_round: Round,
    /// Keeps the last committed round for each authority. This map is used to clean up the dag and
    /// ensure we don't commit twice the same certificate.
    pub last_committed: HashMap<PublicKey, Round>,
    /// Used to populate the index in the sub-dag construction.
    pub latest_sub_dag_index: SequenceNumber,
    /// Keeps the latest committed certificate (and its parents) for every authority. Anything older
    /// must be regularly cleaned up through the function `update`.
    pub dag: Dag,
}

#[allow(clippy::new_without_default)]
impl ConsensusState {
    pub fn new() -> Self {
        Self {
            last_committed_round: 0,
            last_committed: Default::default(),
            latest_sub_dag_index: 0,
            dag: Default::default(),
        }
    }

    pub fn new_from_store(
        recover_last_committed: HashMap<PublicKey, Round>,
        latest_sub_dag_index: SequenceNumber,
        cert_store: CertificateStore,
    ) -> Self {
        let last_committed_round = *recover_last_committed
            .iter()
            .max_by(|a, b| a.1.cmp(b.1))
            .map(|(_k, v)| v)
            .unwrap_or_else(|| &0);
        let dag = Self::construct_dag_from_cert_store(cert_store, &recover_last_committed);

        // TODO(metrics): Increment recovered_consensus_state by 1.

        Self {
            last_committed_round,
            last_committed: recover_last_committed,
            latest_sub_dag_index,
            dag,
        }
    }

    #[instrument(level = "info", skip_all)]
    pub fn construct_dag_from_cert_store(
        cert_store: CertificateStore,
        last_committed: &HashMap<PublicKey, Round>,
    ) -> Dag {
        let mut dag: Dag = BTreeMap::new();
        let min_committed_round = last_committed.values().min().cloned().unwrap_or(0);

        info!(
            "Recreating dag from min committed round: {}",
            min_committed_round,
        );

        // get all certificates at a round > min_round
        let certificates = cert_store.after_round(min_committed_round + 1).unwrap();

        let mut num_certs = 0;
        for cert in &certificates {
            if Self::try_insert_in_dag(&mut dag, last_committed, cert) {
                info!("Inserted certificate: {:?}", cert);
                num_certs += 1;
            }
        }
        info!(
            "Dag is restored and contains {} certs for {} rounds",
            num_certs,
            dag.len()
        );

        dag
    }

    /// Returns true if certificate is inserted in the dag.
    pub fn try_insert(&mut self, certificate: &Certificate) -> bool {
        Self::try_insert_in_dag(&mut self.dag, &self.last_committed, certificate)
    }

    /// Returns true if certificate is inserted in the dag.
    fn try_insert_in_dag(
        dag: &mut Dag,
        last_committed: &HashMap<PublicKey, Round>,
        certificate: &Certificate,
    ) -> bool {
        let origin_last_committed_round = last_committed
            .get(&certificate.origin())
            .cloned()
            .unwrap_or_default();
        if certificate.round() <= origin_last_committed_round {
            debug!(
                "Ignoring certificate {:?} as it is at or before last committed round {} for this origin",
                certificate, origin_last_committed_round
            );
            return false;
        }

        dag.entry(certificate.round())
            .or_default()
            .insert(
                certificate.origin(),
                (certificate.digest(), certificate.clone()),
            )
            .is_none()
    }

    /// Update and clean up internal state after committing a certificate.
    pub fn update(&mut self, certificate: &Certificate, gc_depth: Round) {
        self.last_committed
            .entry(certificate.origin())
            .and_modify(|r| *r = max(*r, certificate.round()))
            .or_insert_with(|| certificate.round());
        self.last_committed_round = max(self.last_committed_round, certificate.round());

        gauge!(
            snarkos_metrics::consensus::LAST_COMMITTED_ROUND,
            self.last_committed_round as f64
        );

        let elapsed = certificate.metadata.created_at.elapsed().as_secs_f64();

        histogram!(
            snarkos_metrics::consensus::CERTIFICATE_COMMIT_LATENCY,
            certificate.metadata.created_at.elapsed().as_secs_f64(),
            "certificate_round" => certificate.round().to_string(),
            "certificate_epoch" => certificate.epoch().to_string(),
        );

        // NOTE: This log entry is used to compute performance.
        tracing::debug!(
            "Certificate {:?} took {} seconds to be committed at round {}",
            certificate.digest(),
            elapsed,
            certificate.round(),
        );

        // Purge all certificates past the gc depth.
        self.dag
            .retain(|r, _| r + gc_depth >= self.last_committed_round);
        // Also purge this certificate, and other certificates at the same origin below its round.
        self.dag.retain(|r, authorities| {
            if r <= &certificate.round() {
                authorities.remove(&certificate.origin());
                !authorities.is_empty()
            } else {
                true
            }
        });
    }
}

/// Describe how to sequence input certificates.
pub trait ConsensusProtocol {
    fn process_certificate(
        &mut self,
        // The state of the consensus protocol.
        state: &mut ConsensusState,
        // The new certificate.
        certificate: Certificate,
    ) -> StoreResult<Vec<CommittedSubDag>>;
}

pub struct Consensus<ConsensusProtocol> {
    /// The committee information.
    committee: Committee,

    /// Receiver for shutdown.
    rx_shutdown: ConditionalBroadcastReceiver,
    /// Receives new certificates from the primary. The primary should send us new certificates only
    /// if it already sent us its whole history.
    rx_new_certificates: mpsc::Receiver<Certificate>,
    /// Outputs the sequence of ordered certificates to the primary (for cleanup and feedback).
    tx_committed_certificates: mpsc::Sender<(Round, Vec<Certificate>)>,
    /// Outputs the highest committed round in the consensus. Controls GC round downstream.
    tx_consensus_round_updates: watch::Sender<Round>,
    /// Outputs the sequence of ordered certificates to the application layer.
    tx_sequence: mpsc::Sender<CommittedSubDag>,

    /// The consensus protocol to run.
    protocol: ConsensusProtocol,

    /// Inner state
    state: ConsensusState,
}

impl<Protocol> Consensus<Protocol>
where
    Protocol: ConsensusProtocol + Send + 'static,
{
    #[must_use]
    pub fn spawn(
        committee: Committee,
        store: Arc<ConsensusStore>,
        cert_store: CertificateStore,
        rx_shutdown: ConditionalBroadcastReceiver,
        rx_new_certificates: mpsc::Receiver<Certificate>,
        tx_committed_certificates: mpsc::Sender<(Round, Vec<Certificate>)>,
        tx_consensus_round_updates: watch::Sender<Round>,
        tx_sequence: mpsc::Sender<CommittedSubDag>,
        protocol: Protocol,
    ) -> JoinHandle<()> {
        // The consensus state (everything else is immutable).
        let recovered_last_committed = store.read_last_committed();
        let latest_sub_dag_index = store.get_latest_sub_dag_index();
        let state = ConsensusState::new_from_store(
            recovered_last_committed,
            latest_sub_dag_index,
            cert_store,
        );
        tx_consensus_round_updates
            .send(state.last_committed_round)
            .expect("Failed to send last_committed_round on initialization!");

        let s = Self {
            committee,
            rx_shutdown,
            rx_new_certificates,
            tx_committed_certificates,
            tx_consensus_round_updates,
            tx_sequence,
            protocol,
            state,
        };

        tokio::spawn(s.run())
    }

    async fn run(self) {
        match self.run_inner().await {
            Ok(_) => {}
            Err(err @ ConsensusError::ShuttingDown) => {
                debug!("{:?}", err)
            }
            Err(err) => panic!("Failed to run consensus: {:?}", err),
        }
    }

    async fn run_inner(mut self) -> Result<(), ConsensusError> {
        // Listen to incoming certificates.
        loop {
            tokio::select! {

                _ = self.rx_shutdown.receiver.recv() => {
                    return Ok(())
                }

                Some(certificate) = self.rx_new_certificates.recv() => {
                    match certificate.epoch().cmp(&self.committee.epoch()) {
                        Ordering::Equal => {
                            // we can proceed.
                        }
                        _ => {
                            tracing::debug!("Already moved to the next epoch");
                            continue
                        }
                    }

                    // Process the certificate using the selected consensus protocol.
                    let committed_sub_dags =
                        self.protocol
                            .process_certificate(&mut self.state, certificate)?;


                    // We extract a list of headers from this specific validator that
                    // have been agreed upon, and signal this back to the narwhal sub-system
                    // to be used to re-send batches that have not made it to a commit.
                    let mut commited_certificates = Vec::new();

                    // Output the sequence in the right order.
                    let mut i = 0;
                    for committed_sub_dag in committed_sub_dags {
                         tracing::debug!("Commit in Sequence {:?}", committed_sub_dag.sub_dag_index);

                        for certificate in &committed_sub_dag.certificates {
                            i+=1;

                            if i % 5_000 == 0 {
                                tracing::debug!("Committed {}", certificate.header);
                            }

                            commited_certificates.push(certificate.clone());
                        }

                        // NOTE: The size of the sub-dag can be arbitrarily large (depending on the network condition
                        // and Byzantine leaders).
                        self.tx_sequence.send(committed_sub_dag).await.map_err(|_|ConsensusError::ShuttingDown)?;
                    }

                    if !commited_certificates.is_empty(){
                        // Highest committed certificate round is the leader round / commit round
                        // expected by primary.
                        let leader_commit_round = commited_certificates.iter().map(|c| c.round()).max().unwrap();

                        self.tx_committed_certificates
                        .send((leader_commit_round, commited_certificates))
                        .await
                        .map_err(|_|ConsensusError::ShuttingDown)?;

                        self.tx_consensus_round_updates.send(leader_commit_round)
                        .map_err(|_|ConsensusError::ShuttingDown)?;
                    }

                    // TODO(metrics): Set consensus_dag_rounds to `self.state.dag.len() as i64`
                },

            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ConsensusState;
    use fastcrypto::{bls12381::min_sig::BLS12381KeyPair, traits::KeyPair};
    use rand::thread_rng;
    use types::Certificate;

    #[test]
    fn test_gc() {
        let mut state = ConsensusState::new();
        // nothing in DAG yet
        assert_eq!(state.dag.len(), 0);
        // create 2 keypairs
        let kp1 = BLS12381KeyPair::generate(&mut thread_rng());
        let pub_key1 = kp1.public();
        let kp2 = BLS12381KeyPair::generate(&mut thread_rng());
        let pub_key2 = kp2.public();

        // create certs with these key pairs
        let mut cert1_kp1 = Certificate::new_test_empty(pub_key1.clone());
        cert1_kp1.header.round = 1;
        let mut cert1_kp2 = Certificate::new_test_empty(pub_key2.clone());
        cert1_kp2.header.round = 1;
        let mut cert2_kp1 = Certificate::new_test_empty(pub_key1.clone());
        cert2_kp1.header.round = 2;
        let mut cert2_kp2 = Certificate::new_test_empty(pub_key2.clone());
        cert2_kp2.header.round = 2;
        let mut cert3_kp1 = Certificate::new_test_empty(pub_key1.clone());
        cert3_kp1.header.round = 3;
        let mut cert3_kp2 = Certificate::new_test_empty(pub_key2.clone());
        cert3_kp2.header.round = 3;
        let mut cert4 = Certificate::new_test_empty(pub_key1.clone());
        cert4.header.round = 4;
        let mut cert5 = Certificate::new_test_empty(pub_key1.clone());
        cert5.header.round = 5;

        // insert them into the DAG
        state.try_insert(&cert1_kp1);
        state.try_insert(&cert1_kp2);
        state.try_insert(&cert2_kp1);
        state.try_insert(&cert2_kp2);
        state.try_insert(&cert3_kp1);
        state.try_insert(&cert3_kp2);
        state.try_insert(&cert4);
        state.try_insert(&cert5);
        assert_eq!(state.dag.len(), 5); // we now have 5 rounds in DAG

        // commit cert3_kp1
        // this also removes everything of _kp1 until round 3
        state.update(&cert3_kp1, 5);
        // nothing is purged yet as the _kp2 certs are still there
        assert_eq!(state.dag.len(), 5);
        // commit cert3_kp2
        // this also removes everything of _kp2 until round 3
        state.update(&cert3_kp2, 5);
        assert_eq!(state.dag.len(), 2);
        // now everything up to round 3 is committed, so only round 4 and 5 are there
    }

    #[test]
    fn test_gc_at_depth_2() {
        let mut state = ConsensusState::new();
        assert_eq!(state.dag.len(), 0);
        let kp1 = BLS12381KeyPair::generate(&mut thread_rng());
        let pub_key1 = kp1.public();
        let kp2 = BLS12381KeyPair::generate(&mut thread_rng());
        let pub_key2 = kp2.public();
        let mut certs = Vec::new();
        for i in 1..=20 {
            let mut cert = Certificate::new_test_empty(pub_key1.clone());
            cert.header.round = i;
            state.try_insert(&cert);
            certs.push(cert);
            let mut cert = Certificate::new_test_empty(pub_key2.clone());
            cert.header.round = i;
            state.try_insert(&cert);
            certs.push(cert);
        }
        assert_eq!(state.dag.len(), 20);
        // 18 & 19 are round 10
        state.update(certs.get(18).unwrap(), 2);
        // all of _kp1 up to round 10 are gone, last committed round = 10
        // GC depth = 2, so rounds 1-7 are gone completely (r + 2 < 10) -> 13 left
        assert_eq!(state.dag.len(), 13);
        state.update(certs.get(19).unwrap(), 2);
        // after this, also all of _kp2 up to round 10 are gone
        // still 10 rounds in DAG
        assert_eq!(state.dag.len(), 10);
    }

    #[test]
    fn test_gc_at_depth_20() {
        let mut state = ConsensusState::new();
        assert_eq!(state.dag.len(), 0);
        let kp1 = BLS12381KeyPair::generate(&mut thread_rng());
        let pub_key1 = kp1.public();
        let kp2 = BLS12381KeyPair::generate(&mut thread_rng());
        let pub_key2 = kp2.public();
        let mut certs = Vec::new();
        for i in 1..=20 {
            let mut cert = Certificate::new_test_empty(pub_key1.clone());
            cert.header.round = i;
            state.try_insert(&cert);
            certs.push(cert);
            let mut cert = Certificate::new_test_empty(pub_key2.clone());
            cert.header.round = i;
            state.try_insert(&cert);
            certs.push(cert);
        }
        assert_eq!(state.dag.len(), 20);
        // 18 & 19 are round 10
        state.update(certs.get(18).unwrap(), 20);
        // all of _kp1 up to round 10 are gone, and at GC depth 20, none of _kp2 are gone, so still 20 rounds in DAG
        assert_eq!(state.dag.len(), 20);
        // after this, also all of _kp2 up to round 10 are gone
        state.update(certs.get(19).unwrap(), 20);
        assert_eq!(state.dag.len(), 10);
        // still 10 rounds in DAG
    }
}

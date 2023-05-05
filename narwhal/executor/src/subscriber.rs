// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use crate::{errors::SubscriberResult, ExecutionState};

use config::{Committee, SharedWorkerCache, WorkerId};
use crypto::{Hash, NetworkPublicKey, PublicKey};

use futures::stream::FuturesOrdered;
use futures::FutureExt;
use futures::StreamExt;

use network::WorkerRpc;

use anyhow::bail;
use std::{sync::Arc, time::Duration, vec};
use tokio::sync::mpsc;

use async_trait::async_trait;
use rand::prelude::SliceRandom;
use rand::rngs::ThreadRng;
use tokio::time::Instant;
use tokio::{sync::oneshot, task::JoinHandle};
use tracing::{debug, error, warn};
use tracing::{info, instrument};
use types::{
    Batch, BatchDigest, Certificate, CommittedSubDag, ConditionalBroadcastReceiver,
    ConsensusOutput, Timestamp,
};

#[cfg(feature = "metrics")]
use snarkos_metrics::histogram;

/// The `Subscriber` receives certificates sequenced by the consensus and waits until the
/// downloaded all the transactions references by the certificates; it then
/// forward the certificates to the Executor Core.
pub struct Subscriber<Network> {
    /// Receiver for shutdown
    rx_shutdown: ConditionalBroadcastReceiver,
    /// A channel to receive sequenced consensus messages.
    rx_sequence: mpsc::Receiver<CommittedSubDag>,

    fetcher: Fetcher<Network>,
}

struct Fetcher<Network> {
    network: Network,
}

pub fn spawn_subscriber<State: ExecutionState + Send + Sync + 'static>(
    name: PublicKey,
    network: oneshot::Receiver<anemo::Network>,
    worker_cache: SharedWorkerCache,
    committee: Committee,
    mut shutdown_receivers: Vec<ConditionalBroadcastReceiver>,
    rx_sequence: mpsc::Receiver<CommittedSubDag>,
    restored_consensus_output: Vec<CommittedSubDag>,
    state: State,
) -> Vec<JoinHandle<()>> {
    // This is ugly but has to be done this way for now
    // Currently network incorporate both server and client side of RPC interface
    // To construct server side we need to set up routes first, which requires starting Primary
    // Some cleanup is needed

    let (tx_notifier, rx_notifier) = mpsc::channel(primary::CHANNEL_CAPACITY);

    let rx_shutdown_notify = shutdown_receivers
        .pop()
        .unwrap_or_else(|| panic!("Not enough shutdown receivers"));
    let rx_shutdown_subscriber = shutdown_receivers
        .pop()
        .unwrap_or_else(|| panic!("Not enough shutdown receivers"));

    vec![
        tokio::spawn(run_notify(state, rx_notifier, rx_shutdown_notify)),
        tokio::spawn(create_and_run_subscriber(
            name,
            network,
            worker_cache,
            committee,
            rx_shutdown_subscriber,
            rx_sequence,
            restored_consensus_output,
            tx_notifier,
        )),
    ]
}

async fn run_notify<State: ExecutionState + Send + Sync + 'static>(
    state: State,
    mut tr_notify: mpsc::Receiver<ConsensusOutput>,
    mut rx_shutdown: ConditionalBroadcastReceiver,
) {
    loop {
        tokio::select! {
            Some(message) = tr_notify.recv() => {
                state.handle_consensus_output(message).await;
            }

            _ = rx_shutdown.receiver.recv() => {
                return
            }

        }
    }
}

async fn create_and_run_subscriber(
    name: PublicKey,
    network: oneshot::Receiver<anemo::Network>,
    worker_cache: SharedWorkerCache,
    committee: Committee,
    rx_shutdown: ConditionalBroadcastReceiver,
    rx_sequence: mpsc::Receiver<CommittedSubDag>,
    restored_consensus_output: Vec<CommittedSubDag>,
    tx_notifier: mpsc::Sender<ConsensusOutput>,
) {
    let network = network.await.expect("Failed to receive network");
    info!("Starting subscriber");
    let network = SubscriberNetworkImpl {
        name,
        worker_cache,
        committee,
        network,
    };
    let fetcher = Fetcher { network };
    let subscriber = Subscriber {
        rx_shutdown,
        rx_sequence,
        fetcher,
    };
    subscriber
        .run(restored_consensus_output, tx_notifier)
        .await
        .expect("Failed to run subscriber")
}

impl<Network: SubscriberNetwork> Subscriber<Network> {
    /// Returns the max amount of pending consensus messages we should expect.
    const MAX_PENDING_PAYLOADS: usize = 32;

    /// Main loop connecting to the consensus to listen to sequence messages.
    async fn run(
        mut self,
        restored_consensus_output: Vec<CommittedSubDag>,
        tx_notifier: mpsc::Sender<ConsensusOutput>,
    ) -> SubscriberResult<()> {
        // It's important to have the futures in ordered fashion as we want
        // to guarantee that will deliver to the executor the certificates
        // in the same order we received from rx_sequence. So it doesn't
        // matter if we somehow managed to fetch the batches from a later
        // certificate. Unless the earlier certificate's payload has been
        // fetched, no later certificate will be delivered.
        let mut waiting = FuturesOrdered::new();

        // First handle any consensus output messages that were restored due to a restart.
        // This needs to happen before we start listening on rx_sequence and receive messages sequenced after these.
        for message in restored_consensus_output {
            let future = self.fetcher.fetch_payloads(message);
            waiting.push_back(future);

            // TODO(metrics): Increment `subscriber_recovered_certificates_count` by 1.
        }

        // Listen to sequenced consensus message and process them.
        loop {
            tokio::select! {
                // Receive the ordered sequence of consensus messages from a consensus node.
                Some(sub_dag) = self.rx_sequence.recv(), if waiting.len() < Self::MAX_PENDING_PAYLOADS => {
                    // We can schedule more then MAX_PENDING_PAYLOADS payloads but
                    // don't process more consensus messages when more
                    // then MAX_PENDING_PAYLOADS is pending
                    waiting.push_back(self.fetcher.fetch_payloads(sub_dag));
                },

                // Receive here consensus messages for which we have downloaded all transactions data.
                Some(message) = waiting.next() => {
                    if let Err(e) = tx_notifier.send(message).await {
                        error!("tx_notifier closed: {}", e);
                        return Ok(());
                    }

                },

                _ = self.rx_shutdown.receiver.recv() => {
                    return Ok(())
                }

            }

            // TODO(metrics): Set `waiting_elements_subscriber` to `waiting.len() as i64`
        }
    }
}

impl<Network: SubscriberNetwork> Fetcher<Network> {
    /// Returns ordered vector of futures for downloading individual payloads for certificate
    /// Order of futures returned follows order of payloads in the certificate
    /// See fetch_payload for more details
    #[instrument(level = "debug", skip_all, fields(certificate = % deliver.leader.digest()))]
    async fn fetch_payloads(&self, deliver: CommittedSubDag) -> ConsensusOutput {
        let num_batches = deliver.num_batches();
        let num_certs = deliver.len();
        if num_batches == 0 {
            debug!("No batches to fetch, payload is empty");
            return ConsensusOutput {
                sub_dag: Arc::new(deliver),
                batches: vec![],
            };
        }

        let sub_dag = Arc::new(deliver);
        let mut subscriber_output = ConsensusOutput {
            sub_dag: sub_dag.clone(),
            batches: Vec::with_capacity(num_certs),
        };

        for cert in &sub_dag.certificates {
            let mut batches = Vec::with_capacity(num_batches);
            let output_cert = cert.clone();

            // TODO(metrics): Set `subscriber_current_round` to `cert.round() as i64`.

            #[cfg(feature = "metrics")]
            histogram!(
                snarkos_metrics::subscribers::CERTIFICATE_LATENCY,
                cert.metadata.created_at.elapsed().as_secs_f64(),
                "certificate_round" => cert.round().to_string(),
                "certificate_epoch" => cert.epoch().to_string(),
            );

            for (digest, (worker_id, _)) in cert.header.payload.iter() {
                // TODO(metrics): Increment `subscriber_processed_batches` by 1.

                let mut workers = self.network.workers_for_certificate(cert, worker_id);

                workers.shuffle(&mut ThreadRng::default());

                debug!(
                    "Scheduling fetching batch {digest} (from certificate {})",
                    cert.digest()
                );
                let batch = self.fetch_payload(*digest, *worker_id, workers).await;
                batches.push(batch);
            }
            subscriber_output.batches.push((output_cert, batches));
        }

        subscriber_output
    }

    /// Fetches single payload from network
    /// This future performs infinite retries and blocks until Batch is available
    /// As an optimization it tries to download from local worker first, but then fans out
    /// requests to remote worker if not found locally
    #[instrument(level = "debug", skip_all, fields(digest = % digest, worker_id = % worker_id))]
    async fn fetch_payload(
        &self,
        digest: BatchDigest,
        worker_id: WorkerId,
        workers: Vec<NetworkPublicKey>,
    ) -> Batch {
        if let Some(payload) = self.try_fetch_locally(digest, worker_id).await {
            let batch_fetch_duration = payload.metadata.created_at.elapsed().as_secs_f64();
            // TODO(metrics): Observe `batch_fetch_duration` as `batch_execution_latency`

            debug!(
                "Batch {:?} took {} seconds to be fetched for execution since creation",
                payload.digest(),
                batch_fetch_duration
            );
            return payload;
        }
        // TODO(metrics): Start `subscriber_remote_fetch_latency` timer.
        let mut stagger = Duration::from_secs(0);
        let mut futures = vec![];
        for worker in workers {
            let future = self.fetch_from_worker(stagger, worker, digest);
            futures.push(future.boxed());
            // TODO: Make this a parameter, and also record workers / authorities that are down
            //       to request from them batches later.
            stagger += Duration::from_millis(200);
        }
        let (batch, _, _) = futures::future::select_all(futures).await;
        let batch_fetch_duration = batch.metadata.created_at.elapsed().as_secs_f64();

        // TODO(metrics): Observe `batch_fetch_duration` as `batch_execution_latency`

        debug!(
            "Batch {:?} took {} seconds to be fetched for execution since creation",
            batch.digest(),
            batch_fetch_duration
        );
        batch
    }

    #[instrument(level = "debug", skip_all, fields(digest = % digest, worker_id = % worker_id))]
    async fn try_fetch_locally(&self, digest: BatchDigest, worker_id: WorkerId) -> Option<Batch> {
        // TODO(metrics): Start `subscriber_local_fetch_latency` timer.
        let worker = self.network.my_worker(&worker_id);
        let payload = self.network.request_batch(digest, worker).await;
        match payload {
            Ok(Some(batch)) => {
                debug!("Payload {} found locally", digest);
                // TODO(metrics): Increment `subscriber_local_hit` by 1.
                return Some(batch);
            }
            Ok(None) => debug!("Payload {} not found locally", digest),
            Err(err) => warn!("Error communicating with own worker: {}", err),
        }
        None
    }

    /// This future performs fetch from given worker
    /// This future performs infinite retries with exponential backoff
    /// You can specify stagger_delay before request is issued
    #[instrument(level = "debug", skip_all, fields(stagger_delay = ? stagger_delay, worker = % worker, digest = % digest))]
    async fn fetch_from_worker(
        &self,
        stagger_delay: Duration,
        worker: NetworkPublicKey,
        digest: BatchDigest,
    ) -> Batch {
        tokio::time::sleep(stagger_delay).await;
        // TODO: Make these config parameters
        let max_timeout = Duration::from_secs(60);
        let mut timeout = Duration::from_secs(10);
        let mut attempt = 0usize;
        loop {
            attempt += 1;
            let deadline = Instant::now() + timeout;
            // TODO(metrics): Increment `pending_remote_request_batch` by 1.
            let payload =
                tokio::time::timeout_at(deadline, self.safe_request_batch(digest, worker.clone()))
                    .await;
            // TODO(metrics): Decrement `pending_remote_request_batch` by 1.
            match payload {
                Ok(Ok(Some(payload))) => return payload,
                Ok(Ok(None)) => error!("[Protocol violation] Payload {} was not found at worker {} while authority signed certificate", digest, worker),
                Ok(Err(err)) => debug!(
                    "Error retrieving payload {} from {}: {}",
                    digest, worker, err
                ),
                Err(_elapsed) => warn!("Timeout retrieving payload {} from {} attempt {}",
                    digest, worker, attempt
                ),
            }
            timeout += timeout / 2;
            timeout = std::cmp::min(max_timeout, timeout);
            // Since the call might have returned before timeout, we wait until originally planned deadline
            tokio::time::sleep_until(deadline).await;
        }
    }

    /// Issue request_batch RPC and verifies response integrity
    async fn safe_request_batch(
        &self,
        digest: BatchDigest,
        worker: NetworkPublicKey,
    ) -> anyhow::Result<Option<Batch>> {
        let payload = self.network.request_batch(digest, worker.clone()).await?;
        if let Some(payload) = payload {
            let payload_digest = payload.digest();
            if payload_digest != digest {
                bail!("[Protocol violation] Worker {} returned batch with mismatch digest {} requested {}", worker, payload_digest, digest );
            } else {
                Ok(Some(payload))
            }
        } else {
            Ok(None)
        }
    }
}

// Trait for unit tests
#[async_trait]
pub trait SubscriberNetwork: Send + Sync {
    fn my_worker(&self, worker_id: &WorkerId) -> NetworkPublicKey;
    fn workers_for_certificate(
        &self,
        certificate: &Certificate,
        worker_id: &WorkerId,
    ) -> Vec<NetworkPublicKey>;
    async fn request_batch(
        &self,
        digest: BatchDigest,
        worker: NetworkPublicKey,
    ) -> anyhow::Result<Option<Batch>>;
}

struct SubscriberNetworkImpl {
    name: PublicKey,
    network: anemo::Network,
    worker_cache: SharedWorkerCache,
    committee: Committee,
}

#[async_trait]
impl SubscriberNetwork for SubscriberNetworkImpl {
    fn my_worker(&self, worker_id: &WorkerId) -> NetworkPublicKey {
        self.worker_cache
            .load()
            .worker(&self.name, worker_id)
            .expect("Own worker not found in cache")
            .name
    }

    fn workers_for_certificate(
        &self,
        certificate: &Certificate,
        worker_id: &WorkerId,
    ) -> Vec<NetworkPublicKey> {
        let authorities = certificate.signed_authorities(&self.committee);
        authorities
            .into_iter()
            .filter_map(|authority| {
                let worker = self.worker_cache.load().worker(&authority, worker_id);
                match worker {
                    Ok(worker) => Some(worker.name),
                    Err(err) => {
                        error!(
                            "Worker {} not found for authority {}: {:?}",
                            worker_id, authority, err
                        );
                        None
                    }
                }
            })
            .collect()
    }

    async fn request_batch(
        &self,
        digest: BatchDigest,
        worker: NetworkPublicKey,
    ) -> anyhow::Result<Option<Batch>> {
        self.network.request_batch(worker, digest).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::{Hash, NetworkKeyPair};
    use fastcrypto::traits::KeyPair;
    use rand::rngs::StdRng;
    use std::collections::HashMap;

    #[tokio::test]
    pub async fn test_fetcher() {
        let mut network = TestSubscriberNetwork::new();
        let batch1 = Batch::new(vec![vec![1]]);
        let batch2 = Batch::new(vec![vec![2]]);
        network.put(&[1, 2], batch1.clone());
        network.put(&[2, 3], batch2.clone());
        let fetcher = Fetcher { network };
        let batch = fetcher
            .fetch_payload(batch1.digest(), 0, test_pks(&[1, 2]))
            .await;
        assert_eq!(batch, batch1);
        let batch = fetcher
            .fetch_payload(batch2.digest(), 0, test_pks(&[2, 3]))
            .await;
        assert_eq!(batch, batch2);
    }

    struct TestSubscriberNetwork {
        data: HashMap<BatchDigest, HashMap<NetworkPublicKey, Batch>>,
        my: NetworkPublicKey,
    }

    impl TestSubscriberNetwork {
        pub fn new() -> Self {
            let my = test_pk(0);
            let data = Default::default();
            Self { data, my }
        }

        pub fn put(&mut self, keys: &[u8], batch: Batch) {
            let digest = batch.digest();
            let entry = self.data.entry(digest).or_default();
            for key in keys {
                let key = test_pk(*key);
                entry.insert(key, batch.clone());
            }
        }
    }

    #[async_trait]
    impl SubscriberNetwork for TestSubscriberNetwork {
        fn my_worker(&self, _worker_id: &WorkerId) -> NetworkPublicKey {
            self.my.clone()
        }

        fn workers_for_certificate(
            &self,
            certificate: &Certificate,
            _worker_id: &WorkerId,
        ) -> Vec<NetworkPublicKey> {
            let digest = certificate.header.payload.keys().next().unwrap();
            self.data.get(digest).unwrap().keys().cloned().collect()
        }

        async fn request_batch(
            &self,
            digest: BatchDigest,
            worker: NetworkPublicKey,
        ) -> anyhow::Result<Option<Batch>> {
            Ok(self.data.get(&digest).unwrap().get(&worker).cloned())
        }
    }

    fn test_pk(i: u8) -> NetworkPublicKey {
        use rand::SeedableRng;
        let mut rng = StdRng::from_seed([i; 32]);
        NetworkKeyPair::generate(&mut rng).public().clone()
    }

    fn test_pks(i: &[u8]) -> Vec<NetworkPublicKey> {
        i.iter().map(|i| test_pk(*i)).collect()
    }
}

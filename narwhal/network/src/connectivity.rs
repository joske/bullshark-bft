// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anemo::PeerId;
use std::collections::HashMap;
use tokio::task::JoinHandle;
use tracing::warn;

#[cfg(feature = "metrics")]
use snarkos_metrics::gauge;

pub struct ConnectionMonitor {
    network: anemo::NetworkRef,

    // Only used with metrics, but not worth the effort to make it conditional.
    // TODO(metrics): Make this conditional at some point?
    #[allow(dead_code)]
    peer_id_types: HashMap<PeerId, String>,
}

impl ConnectionMonitor {
    #[must_use]
    pub fn spawn(
        network: anemo::NetworkRef,
        peer_id_types: HashMap<PeerId, String>,
    ) -> JoinHandle<()> {
        tokio::spawn(
            Self {
                network,
                peer_id_types,
            }
            .run(),
        )
    }

    async fn run(self) {
        let (mut subscriber, connected_peers) = {
            if let Some(network) = self.network.upgrade() {
                let Ok((subscriber, connected_peers)) = network.subscribe() else {
                    return;
                };

                (subscriber, connected_peers)
            } else {
                return;
            }
        };

        /* TODO(metrics)
        // we report first all the known peers as disconnected - so we can see
        // their labels in the metrics reporting tool
        for (_peer_id, _ty) in &self.peer_id_types {
            // TODO(metrics): Set `network_peer_connected` to 0
        }
        */

        // now report the connected peers
        let mut peer_count: usize = connected_peers.len();
        let mut peer_counts = HashMap::<String, usize>::new();

        #[cfg(feature = "metrics")]
        gauge!(snarkos_metrics::network::NETWORK_PEERS, peer_count as f64);

        #[cfg(feature = "metrics")]
        for peer_id in connected_peers {
            self.handle_peer_connect(peer_id, &mut peer_counts);
        }

        while let Ok(event) = subscriber.recv().await {
            if let Some(network) = self.network.upgrade() {
                peer_count = network.peers().len();
                warn!("connected peers: {:?}", &network.peers());
            } else {
                return;
            }
            match event {
                anemo::types::PeerEvent::NewPeer(peer_id) => {
                    _ = peer_id;
                    #[cfg(feature = "metrics")]
                    {
                        gauge!(snarkos_metrics::network::NETWORK_PEERS, peer_count as f64);
                        self.handle_peer_connect(peer_id, &mut peer_counts);
                    }
                }
                anemo::types::PeerEvent::LostPeer(peer_id, _) => {
                    _ = peer_id;
                    #[cfg(feature = "metrics")]
                    {
                        gauge!(snarkos_metrics::network::NETWORK_PEERS, peer_count as f64);
                        self.handle_peer_disconnect(peer_id, &mut peer_counts);
                    }
                }
            }
        }
    }

    #[cfg(feature = "metrics")]
    fn handle_peer_connect(&self, peer_id: PeerId, peer_counts: &mut HashMap<String, usize>) {
        use snarkos_metrics::network::labels::PEER_ID;

        warn!("added connected peer:{peer_id}");
        if let Some(ty) = self.peer_id_types.get(&peer_id) {
            *peer_counts.entry(ty.to_string()).or_insert(0) += 1;
            let count = peer_counts.get(ty).unwrap();
            gauge!(snarkos_metrics::network::NETWORK_PEER_CONNECTED, *count as f64, PEER_ID => ty.to_string());
        }
    }

    #[cfg(feature = "metrics")]
    fn handle_peer_disconnect(&self, peer_id: PeerId, peer_counts: &mut HashMap<String, usize>) {
        use snarkos_metrics::network::labels::PEER_ID;

        warn!("lost connected peer:{peer_id}");
        if let Some(ty) = self.peer_id_types.get(&peer_id) {
            *peer_counts.entry(ty.to_string()).or_insert(0) -= 1; // there should always be an entry if it lost connection
            let count = peer_counts.get(ty).unwrap();
            gauge!(snarkos_metrics::network::NETWORK_PEER_CONNECTED, *count as f64, PEER_ID => ty.to_string());
        }
    }
}

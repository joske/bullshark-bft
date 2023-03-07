// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anemo::PeerId;
use std::collections::HashMap;
use tokio::task::JoinHandle;

pub struct ConnectionMonitor {
    network: anemo::NetworkRef,
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

        // TODO(metrics): Set `network_peers` to `connected_peers.len() as i64`

        // now report the connected peers
        for peer_id in connected_peers {
            self.handle_peer_connect(peer_id);
        }

        while let Ok(event) = subscriber.recv().await {
            match event {
                anemo::types::PeerEvent::NewPeer(peer_id) => {
                    self.handle_peer_connect(peer_id);
                }
                anemo::types::PeerEvent::LostPeer(peer_id, _) => {
                    self.handle_peer_disconnect(peer_id);
                }
            }
        }
    }

    fn handle_peer_connect(&self, peer_id: PeerId) {
        // TODO(metrics): Increment `network_peers` by 1

        if let Some(_ty) = self.peer_id_types.get(&peer_id) {
            // TODO(metrics): Set `network_peer_connected` to 1
        }
    }

    fn handle_peer_disconnect(&self, peer_id: PeerId) {
        // TODO(metrics): Decrement `network_peers` by 1

        if let Some(_ty) = self.peer_id_types.get(&peer_id) {
            // TODO(metrics): Set `network_peer_connected` to 0
        }
    }
}

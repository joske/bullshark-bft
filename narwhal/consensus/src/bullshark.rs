// Copyright (c) 2021, Facebook, Inc. and its affiliates
// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    consensus::{ConsensusProtocol, ConsensusState, Dag},
    utils, ConsensusError, Outcome,
};
use config::{Committee, Stake};
use crypto::PublicKey;
use fastcrypto::traits::EncodeDecodeBase64;
use std::{collections::BTreeSet, sync::Arc};
use tokio::time::Instant;
use tracing::{debug, error_span};
use types::{
    Certificate, CertificateAPI, CertificateDigest, CommittedSubDag, HeaderAPI, ReputationScores,
    Round,
};

#[cfg(feature = "metrics")]
use snarkos_metrics::{gauge, histogram, increment_counter};

#[cfg(test)]
#[path = "tests/bullshark_tests.rs"]
pub mod bullshark_tests;

#[cfg(test)]
#[path = "tests/randomized_tests.rs"]
pub mod randomized_tests;

/// LastRound is a helper struct to keep necessary info
/// around the leader election on the last election round.
/// When both the leader_found = true & leader_has_support = true
/// then we know that we do have a "successful" leader election
/// and consequently a commit.
#[derive(Default)]
pub struct LastRound {
    /// True when the leader has actually proposed a certificate
    /// and found in our DAG
    _leader_found: bool,
    /// When the leader has enough support from downstream
    /// certificates
    leader_has_support: bool,
}

pub struct Bullshark {
    /// The committee information.
    pub committee: Committee,
    /// Persistent storage to safe ensure crash-recovery.
    pub store: Arc<ConsensusStore>,

    /// The last time we had a successful leader election
    pub last_successful_leader_election_timestamp: Instant,
    /// The last round leader election result
    pub last_leader_election: LastRound,
    /// The most recent round of inserted certificate
    pub max_inserted_certificate_round: Round,
    /// The number of committed subdags that will trigger the schedule change and reputation
    /// score reset.
    pub num_sub_dags_per_schedule: u64,
}

impl ConsensusProtocol for Bullshark {
    fn process_certificate(
        &mut self,
        state: &mut ConsensusState,
        certificate: Certificate,
    ) -> Result<(Outcome, Vec<CommittedSubDag>), ConsensusError> {
        debug!("Processing {:?}", certificate);
        let round = certificate.round();

        // Add the new certificate to the local storage.
        if !state.try_insert(&certificate)? {
            // Certificate has not been added to the dag since it's below commit round
            return Ok((Outcome::CertificateBelowCommitRound, vec![]));
        }

        // Report last leader election if was unsuccessful
        // if round > self.max_inserted_certificate_round && round % 2 == 0 {
        //     let _last_election_round = &self.last_leader_election;

        //     // if !last_election_round.leader_found {
        //     //     // TODO(metrics): Increment leader_election_not_found
        //     // } else if !last_election_round.leader_has_support {
        //     //     // TODO(metrics): Increment leader_election_not_enough_support
        //     // }
        // }

        self.max_inserted_certificate_round = self.max_inserted_certificate_round.max(round);

        // Try to order the dag to commit. Start from the highest round for which we have at least
        // f+1 certificates. This is because we need them to provide
        // enough support to the leader.
        let r = round - 1;

        // We only elect leaders for even round numbers.
        if r % 2 != 0 || r < 2 {
            return Ok((Outcome::NoLeaderElectedForOddRound, Vec::new()));
        }

        // Get the certificate's digest of the leader. If we already ordered this leader,
        // there is nothing to do.
        let leader_round = r;
        if leader_round <= state.last_round.committed_round {
            return Ok((Outcome::LeaderBelowCommitRound, Vec::new()));
        }
        let (leader_digest, leader) = match Self::leader(&self.committee, leader_round, &state.dag)
        {
            Some(x) => x,
            None => {
                self.last_leader_election = LastRound {
                    _leader_found: false,
                    leader_has_support: false,
                };
                // leader has not been found - we don't have any certificate
                return Ok((Outcome::LeaderNotFound, Vec::new()));
            }
        };

        // Check if the leader has f+1 support from its children (ie. round r+1).
        let stake: Stake = state
            .dag
            .get(&round)
            .expect("We should have the whole history by now")
            .values()
            .filter(|(_, x)| x.header().parents().contains(leader_digest))
            .map(|(_, x)| self.committee.stake_by_id(x.origin()))
            .sum();

        self.last_leader_election = LastRound {
            _leader_found: true,
            leader_has_support: false,
        };

        // If it is the case, we can commit the leader. But first, we need to recursively go back to
        // the last committed leader, and commit all preceding leaders in the right order. Committing
        // a leader block means committing all its dependencies.
        if stake < self.committee.validity_threshold() {
            debug!("Leader {:?} does not have enough support", leader);
            return Ok((Outcome::NotEnoughSupportForLeader, Vec::new()));
        }

        self.last_leader_election.leader_has_support = true;

        // Get an ordered list of past leaders that are linked to the current leader.
        debug!("Leader {:?} has enough support", leader);
        let mut committed_sub_dags = Vec::new();
        let mut total_committed_certificates = 0;

        // TODO: duplicated in tusk.rs
        for leader in utils::order_leaders(&self.committee, leader, state, Self::leader)
            .iter()
            .rev()
        {
            let sub_dag_index = state.next_sub_dag_index();
            let _span = error_span!("bullshark_process_sub_dag", sub_dag_index);

            debug!("Leader {:?} has enough support", leader);

            let mut min_round = leader.round();
            let mut sequence = Vec::new();

            // Starting from the oldest leader, flatten the sub-dag referenced by the leader.
            for x in utils::order_dag(leader, state) {
                // Update and clean up internal state.
                state.update(&x);

                // For logging.
                min_round = min_round.min(x.round());

                // Add the certificate to the sequence.
                sequence.push(x);
            }
            debug!(min_round, "Subdag has {} certificates", sequence.len());

            total_committed_certificates += sequence.len();

            // We resolve the reputation score that should be stored alongside with this sub dag.
            let reputation_score = self.resolve_reputation_score(state, &sequence, sub_dag_index);

            let sub_dag = CommittedSubDag::new(
                sequence,
                leader.clone(),
                sub_dag_index,
                reputation_score,
                state.last_committed_sub_dag.as_ref(),
            );

            // Persist the update.
            self.store
                .write_consensus_state(&state.last_committed, &sub_dag)?;

            // Update the last sub dag
            state.last_committed_sub_dag = Some(sub_dag.clone());

            committed_sub_dags.push(sub_dag);
        }

        // record the last time we got a successful leader election
        #[cfg(feature = "metrics")]
        let elapsed = self.last_successful_leader_election_timestamp.elapsed();

        #[cfg(feature = "metrics")]
        histogram!(
            snarkos_metrics::consensus::COMMIT_ROUNDS_LATENCY,
            elapsed.as_secs_f64()
        );

        self.last_successful_leader_election_timestamp = Instant::now();

        #[cfg(feature = "metrics")]
        increment_counter!(snarkos_metrics::consensus::LEADERS_ELECTED);

        // The total leader_commits are expected to grow the same amount on validators,
        // but strong vs weak counts are not expected to be the same across validators.

        // TODO(metrics): Increment leader_commits_strong

        // TODO(metrics): Increment leader_commits_strong by `committed_sub_dags.len() as u64 - 1`

        // Log the latest committed round of every authority (for debug).
        // Performance note: if tracing at the debug log level is disabled, this is cheap, see
        // https://github.com/tokio-rs/tracing/pull/326
        for (name, round) in &state.last_committed {
            debug!("Latest commit of {}: Round {}", name, round);
        }

        let total_committed_certificates: usize = committed_sub_dags
            .iter()
            .map(|x| x.certificates.len())
            .sum();
        debug!(
            "Total committed certificates: {}",
            total_committed_certificates
        );

        #[cfg(feature = "metrics")]
        gauge!(
            snarkos_metrics::consensus::COMMITTED_CERTIFICATES,
            total_committed_certificates as f64
        );

        Ok((Outcome::Commit, committed_sub_dags))
    }
}

impl Bullshark {
    /// Create a new Bullshark consensus instance.
    pub fn new(committee: Committee, store: Arc<ConsensusStore>, gc_depth: Round) -> Self {
        Self {
            committee,
            store,
            last_successful_leader_election_timestamp: Instant::now(),
            last_leader_election: LastRound::default(),
            max_inserted_certificate_round: 0,
        }
    }

    // Returns the PublicKey of the authority which is the leader for the provided `round`.
    // Pay attention that this method will return always the first authority as the leader
    // when used under a test environment.
    pub fn leader_authority(committee: &Committee, round: Round) -> AuthorityIdentifier {
        assert_eq!(
            round % 2,
            0,
            "We should never attempt to do a leader election for odd rounds"
        );

        cfg_if::cfg_if! {
            if #[cfg(test)] {
                // We apply round robin in leader election. Since we expect round to be an even number,
                // 2, 4, 6, 8... it can't work well for leader election as we'll omit leaders. Thus
                // we can always divide by 2 to get a monotonically incremented sequence,
                // 2/2 = 1, 4/2 = 2, 6/2 = 3, 8/2 = 4  etc, and then do minus 1 so we can always
                // start with base zero 0.
                let next_leader = (round/2 - 1) as usize % committee.size();
                let authorities = committee.authorities().collect::<Vec<_>>();

                authorities.get(next_leader).unwrap().id()
            } else {
                // Elect the leader in a stake-weighted choice seeded by the round
                committee.leader(round).id()
            }
        }
    }

    // TODO: duplicated in tusk.rs
    /// Returns the certificate (and the certificate's digest) originated by the leader of the
    /// specified round (if any).
    fn leader<'a>(
        committee: &Committee,
        round: Round,
        dag: &'a Dag,
    ) -> Option<&'a (CertificateDigest, Certificate)> {
        // Note: this function is often called with even rounds only. While we do not aim at random selection
        // yet (see issue #10), repeated calls to this function should still pick from the whole roster of leaders.
        let leader = Self::leader_authority(committee, round);

        // Return its certificate and the certificate's digest.
        dag.get(&round).and_then(|x| x.get(&leader))
    }

    /// Calculates the reputation score for the current commit by taking into account the reputation
    /// scores from the previous commit (assuming that exists). It returns the updated reputation score.
    fn resolve_reputation_score(
        &self,
        state: &mut ConsensusState,
        committed_sequence: &[Certificate],
        sub_dag_index: u64,
    ) -> ReputationScores {
        // we reset the scores for every schedule change window, or initialise when it's the first
        // sub dag we are going to create.
        // TODO: when schedule change is implemented we should probably change a little bit
        // this logic here.
        let mut reputation_score =
            if sub_dag_index == 1 || sub_dag_index % self.num_sub_dags_per_schedule == 0 {
                ReputationScores::new(&self.committee)
            } else {
                state
                    .last_committed_sub_dag
                    .as_ref()
                    .expect("Committed sub dag should always exist for sub_dag_index > 1")
                    .reputation_score
                    .clone()
            };

        // update the score for the previous leader. If no previous leader exists,
        // then this is the first time we commit a leader, so no score update takes place
        if let Some(last_committed_sub_dag) = state.last_committed_sub_dag.as_ref() {
            for certificate in committed_sequence {
                // TODO: we could iterate only the certificates of the round above the previous leader's round
                if certificate
                    .header()
                    .parents()
                    .iter()
                    .any(|digest| *digest == last_committed_sub_dag.leader.digest())
                {
                    reputation_score.add_score(certificate.origin(), 1);
                }
            }
        }

        // we check if this is the last sub dag of the current schedule. If yes then we mark the
        // scores as final_of_schedule = true so any downstream user can now that those are the last
        // ones calculated for the current schedule.
        reputation_score.final_of_schedule =
            (sub_dag_index + 1) % self.num_sub_dags_per_schedule == 0;

        // Always ensure that all the authorities are present in the reputation scores - even
        // when score is zero.
        assert_eq!(
            reputation_score.total_authorities() as usize,
            self.committee.size()
        );

        reputation_score
    }
}

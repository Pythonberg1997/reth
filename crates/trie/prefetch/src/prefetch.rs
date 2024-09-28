use std::{collections::HashMap, sync::Arc};

use rayon::prelude::*;
use thiserror::Error;
use tokio::{
    sync::{mpsc::UnboundedReceiver, Mutex, oneshot::Receiver},
    task::JoinSet,
};
use tracing::{debug, trace};

use reth_db::database::Database;
use reth_execution_errors::StorageRootError;
use reth_primitives::{B256, revm_primitives::EvmState};
use reth_provider::{ProviderError, ProviderFactory, providers::ConsistentDbView};
use reth_trie::{
    hashed_cursor::{HashedCursorFactory, HashedPostStateCursorFactory},
    HashedPostState,
    HashedStorage,
    metrics::TrieRootMetrics,
    node_iter::{TrieElement, TrieNodeIter},
    stats::TrieTracker,
    StorageRoot, trie_cursor::TrieCursorFactory, walker::TrieWalker,
};
use reth_trie_db::{DatabaseHashedCursorFactory, DatabaseTrieCursorFactory};
use reth_trie_parallel::{parallel_root::ParallelStateRootError, StorageRootTargets};

/// Prefetch trie storage when executing transactions.
#[derive(Debug, Clone)]
pub struct TriePrefetch {
    /// Cached accounts.
    cached_accounts: HashMap<B256, bool>,
    /// Cached storages.
    cached_storages: HashMap<B256, HashMap<B256, bool>>,
    global_stats: Arc<Mutex<GlobalStats>>,
    /// State trie metrics.
    #[cfg(feature = "metrics")]
    metrics: TrieRootMetrics,
}

#[derive(Default, Debug)]
pub struct GlobalStats {
    pub branch_prefetched: u64,
    pub leaves_prefetched: u64,
    pub missed_leaves_prefetched: u64,
}

impl Default for TriePrefetch {
    fn default() -> Self {
        Self::new()
    }
}

impl TriePrefetch {
    /// Create new `TriePrefetch` instance.
    pub fn new() -> Self {
        Self {
            cached_accounts: HashMap::new(),
            cached_storages: HashMap::new(),
            #[cfg(feature = "metrics")]
            metrics: TrieRootMetrics::default(),
            global_stats: Arc::new(Mutex::new(GlobalStats::default())),
        }
    }

    /// Run the prefetching task.
    pub async fn run<DB>(
        &mut self,
        consistent_view: Arc<ConsistentDbView<DB, ProviderFactory<DB>>>,
        mut prefetch_rx: UnboundedReceiver<EvmState>,
        mut interrupt_rx: Receiver<()>,
    ) where
        DB: Database + 'static,
    {
        let mut join_set = JoinSet::new();

        loop {
            tokio::select! {
                state = prefetch_rx.recv() => {
                    if let Some(state) = state {
                        let consistent_view = Arc::clone(&consistent_view);
                        let hashed_state = self.deduplicate_and_update_cached(state);

                        let self_clone = Arc::new(self.clone());
                        let global_stats = Arc::clone(&self.global_stats);
                        join_set.spawn(async move {
                            if let Err(e) = self_clone.prefetch_once::<DB>(consistent_view, hashed_state, global_stats).await {
                                debug!(target: "trie::trie_prefetch", ?e, "Error while prefetching trie storage");
                            };
                        });
                    }
                }
                _ = &mut interrupt_rx => {
                    debug!(target: "trie::trie_prefetch", "Interrupted trie prefetch task. Unprocessed tx {:?}, Processed accounts: {:?}", prefetch_rx.len(), self.cached_accounts.len());
                    join_set.abort_all();
                    debug!(target: "trie::trie_prefetch", "test info: prefetch account trie node count: {:?}", self.global_stats.lock().await);
                    return
                }
            }
        }
    }

    /// Deduplicate `hashed_state` based on `cached` and update `cached`.
    fn deduplicate_and_update_cached(&mut self, state: EvmState) -> HashedPostState {
        let hashed_state = HashedPostState::from_state(state);
        let mut new_hashed_state = HashedPostState::default();

        // deduplicate accounts if their keys are not present in storages
        for (address, account) in &hashed_state.accounts {
            // if !hashed_state.storages.contains_key(address) &&
            //     !self.cached_accounts.contains_key(address)
            if !self.cached_accounts.contains_key(address)
            {
                self.cached_accounts.insert(*address, true);
                new_hashed_state.accounts.insert(*address, *account);
            }
        }

        // deduplicate storages
        // for (address, storage) in &hashed_state.storages {
        //     let cached_entry = self.cached_storages.entry(*address).or_default();
        // 
        //     // Collect the keys to be added to `new_storage` after filtering
        //     let keys_to_add: Vec<_> = storage
        //         .storage
        //         .iter()
        //         .filter(|(slot, _)| !cached_entry.contains_key(*slot))
        //         .map(|(slot, _)| *slot)
        //         .collect();
        // 
        //     // Iterate over `keys_to_add` to update `cached_entry` and `new_storage`
        //     let new_storage: HashMap<_, _> = keys_to_add
        //         .into_iter()
        //         .map(|slot| {
        //             cached_entry.insert(slot, true);
        //             (slot, *storage.storage.get(&slot).unwrap())
        //         })
        //         .collect();
        // 
        //     if !new_storage.is_empty() {
        //         new_hashed_state
        //             .storages
        //             .insert(*address, HashedStorage::from_iter(false, new_storage.into_iter()));
        // 
        //         if let Some(account) = hashed_state.accounts.get(address) {
        //             new_hashed_state.accounts.insert(*address, *account);
        //         }
        //     }
        // }

        new_hashed_state
    }

    /// Prefetch trie storage for the given hashed state.
    pub async fn prefetch_once<DB>(
        self: Arc<Self>,
        consistent_view: Arc<ConsistentDbView<DB, ProviderFactory<DB>>>,
        hashed_state: HashedPostState,
        global_stats: Arc<Mutex<GlobalStats>>,
    ) -> Result<(), TriePrefetchError>
    where
        DB: Database,
    {
        let mut tracker = TrieTracker::default();
        let mut leaves_missed = 0u64;

        let prefix_sets = hashed_state.construct_prefix_sets().freeze();
        let storage_root_targets = StorageRootTargets::new(
            hashed_state.accounts.keys().copied(),
            prefix_sets.storage_prefix_sets,
        );
        let hashed_state_sorted = hashed_state.into_sorted();

        trace!(target: "trie::trie_prefetch", "start prefetching trie storages");
        let mut storage_roots = storage_root_targets
            .into_par_iter()
            .map(|(hashed_address, prefix_set)| {
                // let provider_ro = consistent_view.provider_ro()?;
                // let trie_cursor_factory = DatabaseTrieCursorFactory::new(provider_ro.tx_ref());
                // let hashed_cursor_factory = HashedPostStateCursorFactory::new(
                //     DatabaseHashedCursorFactory::new(provider_ro.tx_ref()),
                //     &hashed_state_sorted,
                // );
                // let storage_root_result = StorageRoot::new_hashed(
                //     trie_cursor_factory,
                //     hashed_cursor_factory,
                //     hashed_address,
                //     #[cfg(feature = "metrics")]
                //     self.metrics.clone(),
                // )
                // .with_prefix_set(prefix_set)
                // .prefetch();

                Ok((hashed_address, 1))
            })
            .collect::<Result<HashMap<_, _>, ParallelStateRootError>>()?;

        trace!(target: "trie::trie_prefetch", "prefetching account tries");
        let provider_ro = consistent_view.provider_ro()?;
        let tx = provider_ro.tx_ref();
        let trie_cursor_factory = DatabaseTrieCursorFactory::new(tx);
        let hashed_cursor_factory = HashedPostStateCursorFactory::new(
            DatabaseHashedCursorFactory::new(tx),
            &hashed_state_sorted,
        );

        let walker = TrieWalker::new(
            trie_cursor_factory.account_trie_cursor().map_err(ProviderError::Database)?,
            prefix_sets.account_prefix_set,
        )
        .with_deletions_retained(false);
        let mut account_node_iter = TrieNodeIter::new(
            walker,
            hashed_cursor_factory.hashed_account_cursor().map_err(ProviderError::Database)?,
        );

        while let Some(node) = account_node_iter.try_next().map_err(ProviderError::Database)? {
            match node {
                TrieElement::Branch(_) => {
                    tracker.inc_branch();
                }
                TrieElement::Leaf(hashed_address, _) => {
                    match storage_roots.remove(&hashed_address) {
                        Some(result) => {
                            result
                        }
                        // Since we do not store all intermediate nodes in the database, there might
                        // be a possibility of re-adding a non-modified leaf to the hash builder.
                        None => {
                            leaves_missed += 1;

                            StorageRoot::new_hashed(
                                trie_cursor_factory.clone(),
                                hashed_cursor_factory.clone(),
                                hashed_address,
                                #[cfg(feature = "metrics")]
                                self.metrics.clone(),
                            )
                            .prefetch()
                            .ok()
                            .unwrap_or_default()
                        }
                    };
                    tracker.inc_leaf();
                }
            }
        }

        let stats = tracker.finish();

        #[cfg(feature = "metrics")]
        self.metrics.record(stats);

        let mut gstats = global_stats.lock().await;
        gstats.branch_prefetched += stats.branches_added();
        gstats.leaves_prefetched += stats.leaves_added() - leaves_missed;
        gstats.missed_leaves_prefetched += leaves_missed;

        debug!(
            target: "trie::trie_prefetch",
            duration = ?stats.duration(),
            branches_added = stats.branches_added(),
            leaves_added = stats.leaves_added()-leaves_missed,
            leaves_missed = leaves_missed,
            "prefetched account trie"
        );

        Ok(())
    }
}

/// Error during prefetching trie storage.
#[derive(Error, Debug)]
pub enum TriePrefetchError {
    /// Error while calculating storage root.
    #[error(transparent)]
    StorageRoot(#[from] StorageRootError),
    /// Error while calculating parallel storage root.
    #[error(transparent)]
    ParallelStateRoot(#[from] ParallelStateRootError),
    /// Provider error.
    #[error(transparent)]
    Provider(#[from] ProviderError),
}

impl From<TriePrefetchError> for ProviderError {
    fn from(error: TriePrefetchError) -> Self {
        match error {
            TriePrefetchError::Provider(error) => error,
            TriePrefetchError::StorageRoot(StorageRootError::Database(error)) => {
                Self::Database(error)
            }
            TriePrefetchError::ParallelStateRoot(error) => error.into(),
        }
    }
}
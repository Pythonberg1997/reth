//! Contains RPC handler implementations specific to tracing.

use crate::EthApi;
use alloy_eips::BlockId;
use alloy_rpc_types_eth::TransactionInfo;
use reth_bsc_primitives::system_contracts::is_system_transaction;
use reth_chainspec::{ChainSpecProvider, EthChainSpec, EthereumHardforks};
use reth_evm::{system_calls::SystemCaller, ConfigureEvm};
use reth_primitives::{Header, SealedBlockWithSenders};
use reth_revm::database::StateProviderDatabase;
use reth_rpc_eth_api::helpers::{LoadBlock, LoadState, SpawnBlocking, Trace};
use reth_rpc_eth_types::{
    cache::db::{StateCacheDbRefMutWrapper, StateProviderTraitObjWrapper},
    EthApiError, StateCacheDb,
};
use revm::{db::CacheDB, Inspector};
use revm_primitives::{
    db::DatabaseCommit, EnvWithHandlerCfg, EvmState, ExecutionResult, ResultAndState,
};
use std::{future::Future, sync::Arc};

impl<Provider, Pool, Network, EvmConfig> Trace for EthApi<Provider, Pool, Network, EvmConfig>
where
    Self: LoadState<Evm: ConfigureEvm<Header = Header>>,
    Provider: ChainSpecProvider<ChainSpec: EthChainSpec + EthereumHardforks>,
    EvmConfig: ConfigureEvm<Header = Header>,
{
    #[allow(clippy::manual_async_fn)]
    fn trace_block_until_with_inspector<Setup, Insp, F, R>(
        &self,
        block_id: BlockId,
        block: Option<Arc<SealedBlockWithSenders>>,
        highest_index: Option<u64>,
        mut inspector_setup: Setup,
        f: F,
    ) -> impl Future<Output = Result<Option<Vec<R>>, Self::Error>> + Send
    where
        Self: LoadBlock,
        F: Fn(
                TransactionInfo,
                Insp,
                ExecutionResult,
                &EvmState,
                &StateCacheDb<'_>,
            ) -> Result<R, Self::Error>
            + Send
            + 'static,
        Setup: FnMut() -> Insp + Send + 'static,
        Insp: for<'a, 'b> Inspector<StateCacheDbRefMutWrapper<'a, 'b>> + Send + 'static,
        R: Send + 'static,
    {
        async move {
            let block = async {
                if block.is_some() {
                    return Ok(block)
                }
                self.block_with_senders(block_id).await
            };

            let ((cfg, block_env, _), block) =
                futures::try_join!(self.evm_env_at(block_id), block)?;

            let Some(block) = block else { return Ok(None) };

            if block.body.transactions.is_empty() {
                // nothing to trace
                return Ok(Some(Vec::new()))
            }

            let parent_timestamp = self
                .block_with_senders(block.parent_hash.into())
                .await?
                .ok_or(EthApiError::HeaderNotFound(block.parent_hash.into()))?
                .timestamp;

            // replay all transactions of the block
            self.spawn_tracing(move |this| {
                // we need to get the state of the parent block because we're replaying this block
                // on top of its parent block's state
                let state_at = block.parent_hash;
                let block_hash = block.hash();

                let block_number = block_env.number.saturating_to::<u64>();
                let base_fee = block_env.basefee.saturating_to::<u128>();

                // now get the state
                let state = this.state_at_block_id(state_at.into())?;
                let mut db =
                    CacheDB::new(StateProviderDatabase::new(StateProviderTraitObjWrapper(&state)));

                // apply relevant system calls
                SystemCaller::new(this.evm_config().clone(), this.provider().chain_spec())
                    .pre_block_beacon_root_contract_call(
                        &mut db,
                        &cfg,
                        &block_env,
                        block.header().parent_beacon_block_root,
                    )
                    .map_err(|_| {
                        EthApiError::EvmCustom("failed to apply 4788 system call".to_string())
                    })?;

                // prepare transactions, we do everything upfront to reduce time spent with open
                // state
                let max_transactions =
                    highest_index.map_or(block.body.transactions.len(), |highest| {
                        // we need + 1 because the index is 0-based
                        highest as usize + 1
                    });
                let mut results = Vec::with_capacity(max_transactions);

                let mut transactions = block
                    .transactions_with_sender()
                    .take(max_transactions)
                    .enumerate()
                    .map(|(idx, (signer, tx))| {
                        let tx_info = TransactionInfo {
                            hash: Some(tx.hash()),
                            index: Some(idx as u64),
                            block_hash: Some(block_hash),
                            block_number: Some(block_number),
                            base_fee: Some(base_fee),
                        };
                        (tx_info, signer, tx)
                    })
                    .peekable();

                let is_bsc = this.bsc_trace_helper.is_some();
                let mut before_system_tx = is_bsc;

                // try to upgrade system contracts for bsc before all txs if feynman is not active
                if is_bsc {
                    if let Some(trace_helper) = this.bsc_trace_helper.as_ref() {
                        trace_helper
                            .upgrade_system_contracts(&mut db, &block_env, parent_timestamp, true)
                            .map_err(|e| e.into())?;
                    }
                }

                while let Some((tx_info, sender, tx)) = transactions.next() {
                    // check if the transaction is a system transaction
                    // this should be done before return
                    if is_bsc &&
                        before_system_tx &&
                        is_system_transaction(tx, *sender, block_env.coinbase)
                    {
                        if let Some(trace_helper) = this.bsc_trace_helper.as_ref() {
                            // move block reward from the system address to the coinbase
                            trace_helper
                                .add_block_reward(&mut db, &block_env)
                                .map_err(|e| e.into())?;

                            // try to upgrade system contracts between normal txs and system txs
                            // if feynman is active
                            trace_helper
                                .upgrade_system_contracts(
                                    &mut db,
                                    &block_env,
                                    parent_timestamp,
                                    false,
                                )
                                .map_err(|e| e.into())?;
                        }

                        before_system_tx = false;
                    }

                    let tx_env = this.evm_config().tx_env(tx, *sender);
                    #[cfg(feature = "bsc")]
                    let tx_env = {
                        let mut tx_env = tx_env;
                        if !before_system_tx {
                            tx_env.bsc.is_system_transaction = Some(true);
                        };
                        tx_env
                    };

                    let env =
                        EnvWithHandlerCfg::new_with_cfg_env(cfg.clone(), block_env.clone(), tx_env);

                    let mut inspector = inspector_setup();
                    let (res, _) =
                        this.inspect(StateCacheDbRefMutWrapper(&mut db), env, &mut inspector)?;
                    let ResultAndState { result, state } = res;
                    results.push(f(tx_info, inspector, result, &state, &db)?);

                    // need to apply the state changes of this transaction before executing the
                    // next transaction, but only if there's a next transaction
                    if transactions.peek().is_some() {
                        // commit the state changes to the DB
                        db.commit(state)
                    }
                }

                Ok(Some(results))
            })
            .await
        }
    }
}

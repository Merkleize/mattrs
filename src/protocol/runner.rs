//! The engine driving one party's [`Role`] against the chain.

use std::rc::Rc;
use std::time::{Duration, Instant};

use crate::manager::{ContractManager, InstanceHandle, ManagerError};

use super::{Action, ChainView, ContractKey, ProtocolError, Role, StepCtx};

/// How often [`Runner::run`] polls while waiting on the counterparty.
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// What one [`Runner::step`] achieved.
pub enum Progress<O> {
    /// Nothing happened (waiting on the counterparty); poll again later.
    Waiting,
    /// A transition happened (a spend was sent or observed); step again
    /// promptly.
    Advanced,
    /// The protocol resolved with this outcome (returned exactly once).
    Done(O),
}

/// The runner's view of the protocol's live UTXO (its *token*).
enum TokenState<O> {
    /// The token sits at `current`; dispatch the role's arrival handler next.
    Arrived {
        current: InstanceHandle,
        parent: Option<InstanceHandle>,
    },
    /// Watching `current` for the counterparty's spend (and, possibly, for a
    /// timeout deadline).
    Waiting {
        current: InstanceHandle,
        parent: Option<InstanceHandle>,
        timeout: Option<(u32, Box<Action<O>>)>,
    },
    /// The protocol resolved; stepping again is an error.
    Finished,
}

/// Drives one party's [`Role`] from an entry instance to the protocol's
/// outcome: dispatches the role's handlers as the token moves, builds and
/// broadcasts the spends they return, and follows the counterparty's spends
/// by watching the chain.
///
/// The runner owns the party's [`ContractManager`] (its local model of every
/// instance) and performs all chain I/O through a shared [`ChainView`], so the
/// same role runs unchanged against a regtest node or the in-memory
/// [`LocalChain`](super::chain::LocalChain).
pub struct Runner<D, O> {
    role: Role<D, O>,
    data: D,
    manager: ContractManager,
    chain: Rc<dyn ChainView>,
    state: TokenState<O>,
}

impl<D: 'static, O: 'static> Runner<D, O> {
    /// A runner for `role` (with the party's private `data`), starting at the
    /// funded or tracked `entry` instance.
    pub fn new(
        manager: ContractManager,
        chain: Rc<dyn ChainView>,
        role: Role<D, O>,
        data: D,
        entry: InstanceHandle,
    ) -> Self {
        Runner {
            role,
            data,
            manager,
            chain,
            state: TokenState::Arrived {
                current: entry,
                parent: None,
            },
        }
    }

    /// The party's private data.
    pub fn data(&self) -> &D {
        &self.data
    }

    /// The party's private data, mutably.
    pub fn data_mut(&mut self) -> &mut D {
        &mut self.data
    }

    /// The party's contract manager.
    pub fn manager(&self) -> &ContractManager {
        &self.manager
    }

    /// The party's contract manager, mutably.
    pub fn manager_mut(&mut self) -> &mut ContractManager {
        &mut self.manager
    }

    /// The instance the token currently sits at (`None` once finished).
    pub fn current(&self) -> Option<&InstanceHandle> {
        match &self.state {
            TokenState::Arrived { current, .. } | TokenState::Waiting { current, .. } => {
                Some(current)
            }
            TokenState::Finished => None,
        }
    }

    /// Make at most one protocol step, without blocking: dispatch the pending
    /// arrival handler, or poll once for the counterparty's spend (and any
    /// timeout deadline).
    pub fn step(&mut self) -> Result<Progress<O>, ProtocolError> {
        match std::mem::replace(&mut self.state, TokenState::Finished) {
            TokenState::Arrived { current, parent } => {
                let key = ContractKey::of_handle(&current);
                let handler = self.role.arrival(&key).ok_or(ProtocolError::NoHandler {
                    contract: key.name.to_string(),
                })?;
                let action = {
                    let cx = StepCtx {
                        parent: parent.as_ref(),
                        chain: self.chain.as_ref(),
                    };
                    handler(&mut self.data, current.clone(), &cx)?
                };
                self.execute_action(action, current, parent)
            }
            TokenState::Waiting {
                current,
                parent,
                timeout,
            } => self.poll_waiting(current, parent, timeout),
            TokenState::Finished => Err(ProtocolError::Finished),
        }
    }

    /// Drive the protocol to its outcome, polling every 100ms while waiting.
    /// Give up with an error after `window` without progress (`None` = poll
    /// forever, e.g. waiting on a human counterparty).
    pub fn run_within(&mut self, window: Option<Duration>) -> Result<O, ProtocolError> {
        let mut last_progress = Instant::now();
        loop {
            match self.step()? {
                Progress::Done(outcome) => return Ok(outcome),
                Progress::Advanced => last_progress = Instant::now(),
                Progress::Waiting => {
                    if let Some(window) = window {
                        if last_progress.elapsed() >= window {
                            let outpoint = self
                                .current()
                                .and_then(|h| h.outpoint())
                                .ok_or(ManagerError::NotFunded)?;
                            return Err(ManagerError::SpendNotFound(outpoint).into());
                        }
                    }
                    std::thread::sleep(POLL_INTERVAL);
                }
            }
        }
    }

    /// [`run_within`](Runner::run_within) with no time limit.
    pub fn run(&mut self) -> Result<O, ProtocolError> {
        self.run_within(None)
    }

    /// Carry out a handler's decision for the token at `current`.
    fn execute_action(
        &mut self,
        action: Action<O>,
        current: InstanceHandle,
        parent: Option<InstanceHandle>,
    ) -> Result<Progress<O>, ProtocolError> {
        match action {
            Action::Send(builder) => {
                let tx = builder.build_tx(&self.manager)?;
                self.chain.broadcast(&tx)?;
                let children = self.manager.observe_spend(&current, &tx)?;
                self.follow_spend(children, current, parent)
            }
            Action::SendFinal(builder, outcome) => {
                let tx = builder.build_tx(&self.manager)?;
                self.chain.broadcast(&tx)?;
                self.manager.observe_spend(&current, &tx)?;
                self.state = TokenState::Finished;
                Ok(Progress::Done(outcome))
            }
            Action::Wait => {
                self.state = TokenState::Waiting {
                    current,
                    parent,
                    timeout: None,
                };
                // Poll right away: the spend may already be there (e.g. an
                // observer catching up on an old game).
                self.step()
            }
            Action::WaitWithTimeout { blocks, on_timeout } => {
                self.state = TokenState::Waiting {
                    current,
                    parent,
                    timeout: Some((blocks, on_timeout)),
                };
                self.step()
            }
            Action::Finish(outcome) => {
                self.state = TokenState::Finished;
                Ok(Progress::Done(outcome))
            }
        }
    }

    /// One poll of a waited-on instance: the counterparty's spend first, then
    /// the timeout deadline.
    fn poll_waiting(
        &mut self,
        current: InstanceHandle,
        parent: Option<InstanceHandle>,
        timeout: Option<(u32, Box<Action<O>>)>,
    ) -> Result<Progress<O>, ProtocolError> {
        let outpoint = current.outpoint().ok_or(ManagerError::NotFunded)?;

        if let Some(tx) = self.chain.find_spending_tx(outpoint)? {
            let children = self.manager.observe_spend(&current, &tx)?;
            return self.follow_spend(children, current, parent);
        }

        if let Some((blocks, on_timeout)) = timeout {
            let confirmed = self.chain.confirmation_height(outpoint.txid)?;
            let deadline =
                confirmed.map(|conf| conf.saturating_add(blocks).saturating_sub(1));
            if deadline.is_some_and(|d| self.chain.height().is_ok_and(|h| h >= d)) {
                return match *on_timeout {
                    Action::Wait | Action::WaitWithTimeout { .. } => {
                        Err(ProtocolError::InvalidTimeoutAction)
                    }
                    action => self.execute_action(action, current, parent),
                };
            }
            self.state = TokenState::Waiting {
                current,
                parent,
                timeout: Some((blocks, on_timeout)),
            };
        } else {
            self.state = TokenState::Waiting {
                current,
                parent,
                timeout: None,
            };
        }
        Ok(Progress::Waiting)
    }

    /// Move the token along an observed (or just-sent) spend of `current`:
    /// follow the child the role can handle, or — when the spend is terminal —
    /// classify it through the role's settlement handler.
    fn follow_spend(
        &mut self,
        children: Vec<InstanceHandle>,
        current: InstanceHandle,
        parent: Option<InstanceHandle>,
    ) -> Result<Progress<O>, ProtocolError> {
        if children.is_empty() {
            let key = ContractKey::of_handle(&current);
            let settler = self.role.settlement(&key).ok_or(ProtocolError::NoHandler {
                contract: format!("{} (settlement)", key.name),
            })?;
            let cx = StepCtx {
                parent: parent.as_ref(),
                chain: self.chain.as_ref(),
            };
            let outcome = settler(&mut self.data, current.clone(), &cx)?;
            self.state = TokenState::Finished;
            return Ok(Progress::Done(outcome));
        }

        let followable: Vec<&InstanceHandle> = children
            .iter()
            .filter(|c| self.role.handles_arrival(&ContractKey::of_handle(c)))
            .collect();
        match followable[..] {
            [next] => {
                self.state = TokenState::Arrived {
                    current: next.clone(),
                    parent: Some(current),
                };
                Ok(Progress::Advanced)
            }
            [] => Err(ProtocolError::NoHandler {
                contract: children
                    .iter()
                    .map(|c| c.contract_name())
                    .collect::<Vec<_>>()
                    .join(", "),
            }),
            _ => Err(ProtocolError::AmbiguousChildren {
                contracts: followable.iter().map(|c| c.contract_name()).collect(),
            }),
        }
    }
}

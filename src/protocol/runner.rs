//! The engine driving one party's [`Role`] against the chain.

use std::rc::Rc;
use std::time::{Duration, Instant};

use crate::manager::{ContractManager, InstanceHandle, ManagerError};

use super::{Action, ChainView, ContractKey, ProtocolError, Role, StepCtx, TimeoutAction};

/// How often [`Runner::run`] polls while waiting on the counterparty.
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// What one [`Runner::step`] achieved.
#[derive(Debug)]
pub enum Progress<O> {
    /// Nothing happened (waiting on the counterparty); poll again later.
    Waiting,
    /// Something happened (a spend was sent or observed, a token forked or
    /// resolved); step again promptly.
    Advanced,
    /// Every token resolved; the outcomes, in resolution order (returned
    /// exactly once).
    Done(Vec<O>),
}

/// The runner's view of one live UTXO it follows (a *token*).
struct TokenState<O> {
    /// The instance the token sits at.
    current: InstanceHandle,
    /// The spent instance whose clause created `current` (`None` for the
    /// entry).
    parent: Option<InstanceHandle>,
    phase: Phase<O>,
}

enum Phase<O> {
    /// Dispatch the role's arrival handler next.
    Arrived,
    /// Watching for the counterparty's spend (and, possibly, for a timeout
    /// deadline).
    Waiting(Option<Timeout<O>>),
}

/// A pending timeout of a waited-on token.
struct Timeout<O> {
    /// Confirmations of the current UTXO after which the fallback fires.
    blocks: u32,
    /// The absolute height the fallback fires at, resolved (and then cached —
    /// a confirmation height never changes) once the watched UTXO confirms.
    deadline: Option<u32>,
    on_timeout: TimeoutAction<O>,
}

/// What stepping one token once did to it.
enum TokenStep<O> {
    /// The token is still live (`advanced` says whether it moved).
    Keep(TokenState<O>, bool),
    /// A spend was followed into several handled children: the token forked.
    Fork(Vec<TokenState<O>>),
    /// The token resolved — with an outcome, or silently (`None`) when every
    /// child of its final spend was ignored.
    Resolved(Option<O>),
}

/// Drives one party's [`Role`] from an entry instance to the protocol's
/// outcomes: dispatches the role's handlers as tokens move, builds and
/// broadcasts the spends they return, and follows the counterparty's spends
/// by watching the chain.
///
/// The runner starts with a single token (the entry instance). A spend forking
/// into several handled children splits the token, and each child is followed
/// independently — with its own turn-taking and timeout deadline — until it
/// resolves an outcome. The protocol is done when no token is left.
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
    /// The live tokens; empty once the protocol resolved (or a step failed).
    tokens: Vec<TokenState<O>>,
    outcomes: Vec<O>,
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
            tokens: vec![TokenState {
                current: entry,
                parent: None,
                phase: Phase::Arrived,
            }],
            outcomes: Vec::new(),
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

    /// The instances the live tokens currently sit at (empty once done).
    pub fn tokens(&self) -> Vec<&InstanceHandle> {
        self.tokens.iter().map(|t| &t.current).collect()
    }

    /// The instance the token sits at, when exactly one token is live (`None`
    /// once finished or while several tokens are in flight).
    pub fn current(&self) -> Option<&InstanceHandle> {
        match &self.tokens[..] {
            [only] => Some(&only.current),
            _ => None,
        }
    }

    /// The outcomes resolved so far (in resolution order). [`Progress::Done`]
    /// hands them over when the last token resolves; until then this peeks at
    /// the partial list — useful for long-lived roles (e.g. a watchtower)
    /// whose remaining tokens may outlive the interesting resolution.
    pub fn outcomes(&self) -> &[O] {
        &self.outcomes
    }

    /// Step every live token at most once, without blocking: dispatch pending
    /// arrival handlers, or poll once for counterparty spends (and timeout
    /// deadlines).
    ///
    /// An error poisons the runner: the failing step is not retried (the
    /// tokens are dropped), and stepping again returns
    /// [`ProtocolError::Finished`].
    pub fn step(&mut self) -> Result<Progress<O>, ProtocolError> {
        if self.tokens.is_empty() {
            return Err(ProtocolError::Finished);
        }
        let mut advanced = false;
        let mut kept = Vec::new();
        for token in std::mem::take(&mut self.tokens) {
            match self.step_token(token)? {
                TokenStep::Keep(t, adv) => {
                    advanced |= adv;
                    kept.push(t);
                }
                TokenStep::Fork(ts) => {
                    advanced = true;
                    kept.extend(ts);
                }
                TokenStep::Resolved(o) => {
                    advanced = true;
                    self.outcomes.extend(o);
                }
            }
        }
        self.tokens = kept;
        if self.tokens.is_empty() {
            return Ok(Progress::Done(std::mem::take(&mut self.outcomes)));
        }
        Ok(if advanced {
            Progress::Advanced
        } else {
            Progress::Waiting
        })
    }

    /// Drive the protocol to its outcomes, polling every 100ms while waiting.
    /// Give up with an error after `window` without progress (`None` = poll
    /// forever, e.g. waiting on a human counterparty).
    pub fn run_within(&mut self, window: Option<Duration>) -> Result<Vec<O>, ProtocolError> {
        let mut last_progress = Instant::now();
        loop {
            match self.step()? {
                Progress::Done(outcomes) => return Ok(outcomes),
                Progress::Advanced => last_progress = Instant::now(),
                Progress::Waiting => {
                    if let Some(window) = window
                        && last_progress.elapsed() >= window
                    {
                        let outpoint = self
                            .tokens
                            .first()
                            .and_then(|t| t.current.outpoint())
                            .ok_or(ManagerError::NotFunded)?;
                        return Err(ManagerError::SpendNotFound(outpoint).into());
                    }
                    std::thread::sleep(POLL_INTERVAL);
                }
            }
        }
    }

    /// [`run_within`](Runner::run_within) with no time limit.
    pub fn run(&mut self) -> Result<Vec<O>, ProtocolError> {
        self.run_within(None)
    }

    /// [`run_within`](Runner::run_within) for a protocol expected not to fork:
    /// the single outcome, or an error if the tokens resolved any other number.
    pub fn run_one_within(&mut self, window: Option<Duration>) -> Result<O, ProtocolError> {
        let mut outcomes = self.run_within(window)?;
        if outcomes.len() != 1 {
            return Err(ProtocolError::Other(format!(
                "the protocol resolved {} outcomes where exactly one was expected",
                outcomes.len()
            )));
        }
        Ok(outcomes.remove(0))
    }

    /// [`run_one_within`](Runner::run_one_within) with no time limit.
    pub fn run_one(&mut self) -> Result<O, ProtocolError> {
        self.run_one_within(None)
    }

    /// Step one token once.
    fn step_token(&mut self, token: TokenState<O>) -> Result<TokenStep<O>, ProtocolError> {
        let TokenState {
            current,
            parent,
            phase,
        } = token;
        match phase {
            Phase::Arrived => {
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
            Phase::Waiting(timeout) => self.poll_waiting(current, parent, timeout),
        }
    }

    /// Carry out a handler's decision for the token at `current`.
    fn execute_action(
        &mut self,
        action: Action<O>,
        current: InstanceHandle,
        parent: Option<InstanceHandle>,
    ) -> Result<TokenStep<O>, ProtocolError> {
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
                Ok(TokenStep::Resolved(Some(outcome)))
            }
            // Poll right away: the spend may already be there (e.g. an
            // observer catching up on an old game).
            Action::Wait => self.poll_waiting(current, parent, None),
            Action::WaitWithTimeout { blocks, on_timeout } => self.poll_waiting(
                current,
                parent,
                Some(Timeout {
                    blocks,
                    deadline: None,
                    on_timeout,
                }),
            ),
            Action::Finish(outcome) => Ok(TokenStep::Resolved(Some(outcome))),
        }
    }

    /// One poll of a waited-on instance: the counterparty's spend first, then
    /// the timeout deadline.
    fn poll_waiting(
        &mut self,
        current: InstanceHandle,
        parent: Option<InstanceHandle>,
        mut timeout: Option<Timeout<O>>,
    ) -> Result<TokenStep<O>, ProtocolError> {
        let outpoint = current.outpoint().ok_or(ManagerError::NotFunded)?;

        if let Some(tx) = self.chain.find_spending_tx(outpoint)? {
            let children = self.manager.observe_spend(&current, &tx)?;
            return self.follow_spend(children, current, parent);
        }

        if let Some(t) = &mut timeout {
            if t.deadline.is_none() {
                t.deadline = self
                    .chain
                    .confirmation_height(outpoint.txid)?
                    .map(|conf| conf.saturating_add(t.blocks).saturating_sub(1));
            }
            if let Some(d) = t.deadline
                && self.chain.height()? >= d
            {
                let t = timeout.expect("checked above");
                return self.execute_action(t.on_timeout.into(), current, parent);
            }
        }
        Ok(TokenStep::Keep(
            TokenState {
                current,
                parent,
                phase: Phase::Waiting(timeout),
            },
            false,
        ))
    }

    /// Move the token along an observed (or just-sent) spend of `current`:
    /// follow every child the role handles (forking the token if there are
    /// several), or — when the spend is terminal — classify it through the
    /// role's settlement handler.
    fn follow_spend(
        &mut self,
        children: Vec<InstanceHandle>,
        current: InstanceHandle,
        parent: Option<InstanceHandle>,
    ) -> Result<TokenStep<O>, ProtocolError> {
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
            return Ok(TokenStep::Resolved(Some(outcome)));
        }

        let mut followed = Vec::new();
        for child in children {
            let key = ContractKey::of_handle(&child);
            if self.role.handles_arrival(&key) {
                followed.push(TokenState {
                    current: child,
                    parent: Some(current.clone()),
                    phase: Phase::Arrived,
                });
            } else if !self.role.ignores(&key) {
                return Err(ProtocolError::NoHandler {
                    contract: key.name.to_string(),
                });
            }
        }
        Ok(match followed.len() {
            // Every child ignored: this branch is not our business.
            0 => TokenStep::Resolved(None),
            1 => TokenStep::Keep(followed.pop().expect("len 1"), true),
            _ => TokenStep::Fork(followed),
        })
    }
}

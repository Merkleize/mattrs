//! Declarative multi-party protocols on top of the contract layer.
//!
//! The `contract!` DSL defines how a single CCV-encumbered UTXO can evolve; this
//! module layers the *protocol* on top: which party sends which transaction when
//! a state is reached. Each party is described by a [`Role`] — a table mapping
//! contract types to handlers that return an [`Action`] (send this spend, wait
//! for the counterparty, wait with a timeout fallback, or finish with an
//! outcome). A [`Runner`] drives a role against the chain (a [`ChainView`]),
//! following the protocol's live UTXO (its *token*) from state to state until
//! the role resolves an outcome.
//!
//! Roles compose: [`Role::embed`] mounts a sub-protocol's roles into a larger
//! protocol, mapping the sub-protocol's outcomes into the outer protocol's own
//! outcome type. The outer role never handles the sub-protocol's internal
//! states — see [`crate::fraud::roles`] for the bisection fraud proof packaged
//! this way.
//!
//! Protocols may *fork*: a spend can produce several covenant children (e.g. the
//! vault's `trigger_and_revault`), and the runner then follows each as its own
//! token, resolving one outcome per token. Every child must be either handled
//! ([`Role::on`]) or explicitly declared irrelevant ([`Role::ignore`]) — an
//! unexpected child is a loud error, never a silently orphaned branch.
//!
//! Scope: each action spends a single token; transactions batching several
//! tokens' UTXOs as inputs are a future extension.

pub mod chain;
mod runner;

use std::any::TypeId;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use crate::contracts::WitnessError;
use crate::manager::{
    InstanceHandle, ManagerError, MissingStateError, SpendBuilder, WrongContractType,
};

pub use chain::{ChainView, LocalChain, RpcChain};
pub use runner::{Progress, Runner};

/// Bridge from a `contract!`-generated contract type to its typed handle and
/// dispatch key. Implemented by the `contract!` macro; never by hand.
pub trait TypedContract {
    /// The generated typed handle (`NameHandle`).
    type Handle: TryFrom<InstanceHandle, Error = WrongContractType> + Clone + 'static;

    /// The contract's name (matches
    /// [`ErasedContract::contract_name`](crate::contracts::ErasedContract::contract_name)).
    const NAME: &'static str;

    /// The `TypeId` of the erased contract backing this type.
    fn kind_id() -> TypeId;

    /// The dispatch key of this contract type.
    fn kind() -> ContractKey {
        ContractKey {
            type_id: Self::kind_id(),
            name: Self::NAME,
        }
    }
}

/// The key a [`Role`] dispatches on: the erased contract's `TypeId` *and* its
/// name. Two `contract!` definitions sharing parameter and state types share a
/// `TypeId` (they erase to the same `StandardP2TR`/`StandardAugmentedP2TR`
/// instantiation), so the name disambiguates them.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ContractKey {
    /// The erased contract's `TypeId`.
    pub type_id: TypeId,
    /// The contract's name.
    pub name: &'static str,
}

impl ContractKey {
    /// The dispatch key of a live instance.
    pub fn of_handle(handle: &InstanceHandle) -> Self {
        ContractKey {
            type_id: handle.contract_type_id(),
            name: handle.contract_name(),
        }
    }
}

/// What a party does when the protocol token arrives at a contract state.
pub enum Action<O> {
    /// My turn: broadcast this spend and follow its child instance.
    Send(SpendBuilder),
    /// My final spend: broadcast it and finish with this outcome (children, if
    /// any, are the counterparty's business).
    SendFinal(SpendBuilder, O),
    /// The counterparty's turn: watch the UTXO for its spend.
    Wait,
    /// The counterparty's turn, with a deadline: once the current UTXO is
    /// `blocks` confirmations deep and still unspent, take the fallback action
    /// (e.g. a `forfait` spend). A timeout clause is CSV-gated, so the fallback's
    /// builder must set `.sequence(blocks)` itself (and, for a terminal clause,
    /// `.outputs(..)`). The fallback must act — a nested `Wait` is an error.
    WaitWithTimeout {
        /// Confirmations of the current UTXO after which the fallback fires.
        blocks: u32,
        /// The action taken when the deadline passes.
        on_timeout: Box<Action<O>>,
    },
    /// The protocol is over for this party; no transaction from us.
    Finish(O),
}

/// How the protocol token got to the state a handler runs at.
pub struct StepCtx<'a> {
    /// The spent instance whose clause created the current one (`None` for the
    /// protocol's entry instance). Its
    /// [`clause_name`](InstanceHandle::clause_name) and
    /// [`spending_args`](InstanceHandle::spending_args) carry what the
    /// counterparty revealed on the way here.
    pub parent: Option<&'a InstanceHandle>,
    /// Read-only chain access (e.g. the current height).
    pub chain: &'a dyn ChainView,
}

/// An error raised while declaring or driving a protocol role.
#[derive(Debug)]
pub enum ProtocolError {
    /// An underlying manager operation failed.
    Manager(ManagerError),
    /// Decoding witness data or contract parameters failed.
    Witness(WitnessError),
    /// A handler ran against an instance of the wrong contract type.
    WrongContract(WrongContractType),
    /// A typed spend needed instance state that is not there.
    MissingState(MissingStateError),
    /// The token reached a contract this role neither handles nor ignores.
    NoHandler {
        /// The name of the unhandled contract.
        contract: String,
    },
    /// A timeout fallback was a `Wait`-family action; it must send or finish.
    InvalidTimeoutAction,
    /// The runner was stepped after the protocol already resolved.
    Finished,
    /// A protocol-specific failure raised by a role handler (e.g. the
    /// counterparty broke an off-chain commitment).
    Other(String),
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtocolError::Manager(e) => write!(f, "manager error: {}", e),
            ProtocolError::Witness(e) => write!(f, "witness error: {}", e),
            ProtocolError::WrongContract(e) => write!(f, "{}", e),
            ProtocolError::MissingState(e) => write!(f, "{}", e),
            ProtocolError::NoHandler { contract } => {
                write!(f, "the role has no handler for contract `{}`", contract)
            }
            ProtocolError::InvalidTimeoutAction => {
                write!(f, "a timeout fallback must send or finish, not wait")
            }
            ProtocolError::Finished => write!(f, "the protocol already resolved"),
            ProtocolError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for ProtocolError {}

impl From<ManagerError> for ProtocolError {
    fn from(e: ManagerError) -> Self {
        ProtocolError::Manager(e)
    }
}

impl From<WitnessError> for ProtocolError {
    fn from(e: WitnessError) -> Self {
        ProtocolError::Witness(e)
    }
}

impl From<WrongContractType> for ProtocolError {
    fn from(e: WrongContractType) -> Self {
        ProtocolError::WrongContract(e)
    }
}

impl From<MissingStateError> for ProtocolError {
    fn from(e: MissingStateError) -> Self {
        ProtocolError::MissingState(e)
    }
}

pub(crate) type ArrivalFn<D, O> =
    Rc<dyn Fn(&mut D, InstanceHandle, &StepCtx<'_>) -> Result<Action<O>, ProtocolError>>;
pub(crate) type SettledFn<D, O> =
    Rc<dyn Fn(&mut D, InstanceHandle, &StepCtx<'_>) -> Result<O, ProtocolError>>;
type OutcomeMapFn<D, O2, O> = dyn Fn(&mut D, O2) -> Result<O, ProtocolError>;

/// One party's protocol strategy, declared as a table: for each contract type,
/// what to do when the token arrives there ([`on`](Role::on)) and how to
/// classify a terminal spend made by the counterparty
/// ([`on_settled`](Role::on_settled)).
///
/// `D` is the party's private data (keys, secrets, computed traces — anything
/// the handlers need); `O` is the protocol's outcome type. A whole protocol's
/// role can be mounted inside a larger one with [`embed`](Role::embed).
pub struct Role<D, O> {
    arrivals: HashMap<ContractKey, ArrivalFn<D, O>>,
    settlements: HashMap<ContractKey, SettledFn<D, O>>,
    ignored: HashSet<ContractKey>,
}

impl<D: 'static, O: 'static> Default for Role<D, O> {
    fn default() -> Self {
        Self::new()
    }
}

impl<D: 'static, O: 'static> Role<D, O> {
    /// An empty role; chain [`on`](Role::on) / [`on_settled`](Role::on_settled)
    /// / [`embed`](Role::embed) onto it.
    pub fn new() -> Self {
        Role {
            arrivals: HashMap::new(),
            settlements: HashMap::new(),
            ignored: HashSet::new(),
        }
    }

    /// Declare what this party does when the token arrives at a live `C`
    /// instance.
    ///
    /// # Panics
    ///
    /// Panics if the role already handles `C` arrivals (a role maps each state
    /// to one reaction), or already ignores `C`.
    pub fn on<C, F>(mut self, f: F) -> Self
    where
        C: TypedContract,
        F: Fn(&mut D, C::Handle, &StepCtx<'_>) -> Result<Action<O>, ProtocolError> + 'static,
    {
        let key = C::kind();
        assert!(
            !self.arrivals.contains_key(&key),
            "role already has an arrival handler for contract `{}`",
            C::NAME
        );
        assert!(
            !self.ignored.contains(&key),
            "role already ignores contract `{}`",
            C::NAME
        );
        self.arrivals.insert(
            key,
            Rc::new(move |d, h, cx| {
                let typed = C::Handle::try_from(h)?;
                f(d, typed, cx)
            }),
        );
        self
    }

    /// Declare how this party classifies a *terminal* spend of a `C` instance
    /// made by the counterparty (a spend producing no child instances, e.g. a
    /// CTV payout). The spent handle's
    /// [`clause_name`](InstanceHandle::clause_name) and
    /// [`spending_args`](InstanceHandle::spending_args) identify what happened.
    ///
    /// # Panics
    ///
    /// Panics if the role already handles `C` settlements.
    pub fn on_settled<C, F>(mut self, f: F) -> Self
    where
        C: TypedContract,
        F: Fn(&mut D, C::Handle, &StepCtx<'_>) -> Result<O, ProtocolError> + 'static,
    {
        let key = C::kind();
        assert!(
            !self.settlements.contains_key(&key),
            "role already has a settlement handler for contract `{}`",
            C::NAME
        );
        self.settlements.insert(
            key,
            Rc::new(move |d, h, cx| {
                let typed = C::Handle::try_from(h)?;
                f(d, typed, cx)
            }),
        );
        self
    }

    /// Declare `C` children as not this party's business: when a spend forks,
    /// `C` children are dropped instead of followed (any child neither handled
    /// nor ignored is a [`NoHandler`](ProtocolError::NoHandler) error). A token
    /// *all* of whose children are ignored resolves silently, contributing no
    /// outcome.
    ///
    /// # Panics
    ///
    /// Panics if the role already handles or ignores `C`.
    pub fn ignore<C: TypedContract>(mut self) -> Self {
        let key = C::kind();
        assert!(
            !self.arrivals.contains_key(&key),
            "role already has an arrival handler for contract `{}`",
            C::NAME
        );
        assert!(
            self.ignored.insert(key),
            "role already ignores contract `{}`",
            C::NAME
        );
        self
    }

    /// Mount a sub-protocol: merge `sub`'s handlers into this role, viewing the
    /// sub-protocol's party data through `lens` and mapping its outcomes into
    /// this protocol's through `map`.
    ///
    /// Once the token enters one of the sub-protocol's contracts, the mounted
    /// handlers drive it; this role only sees the mapped outcome. `lens` must
    /// be a plain (non-capturing) field projection, e.g.
    /// `|d: &mut GameData| &mut d.fraud`.
    ///
    /// # Panics
    ///
    /// Panics if `sub` handles a contract this role already handles, or if one
    /// side ignores a contract the other handles.
    pub fn embed<D2: 'static, O2: 'static>(
        mut self,
        sub: Role<D2, O2>,
        lens: fn(&mut D) -> &mut D2,
        map: impl Fn(&mut D, O2) -> Result<O, ProtocolError> + 'static,
    ) -> Self {
        let map: Rc<OutcomeMapFn<D, O2, O>> = Rc::new(map);
        for key in sub.ignored {
            assert!(
                !self.arrivals.contains_key(&key),
                "embedded role ignores contract `{}`, which this role handles",
                key.name
            );
            self.ignored.insert(key);
        }
        for (key, sub_handler) in sub.arrivals {
            assert!(
                !self.arrivals.contains_key(&key),
                "embedded role clashes on arrival handler for contract `{}`",
                key.name
            );
            assert!(
                !self.ignored.contains(&key),
                "embedded role handles contract `{}`, which this role ignores",
                key.name
            );
            let map = map.clone();
            self.arrivals.insert(
                key,
                Rc::new(move |d, h, cx| {
                    let action = sub_handler(lens(d), h, cx)?;
                    map_action(d, action, map.as_ref())
                }),
            );
        }
        for (key, sub_settler) in sub.settlements {
            assert!(
                !self.settlements.contains_key(&key),
                "embedded role clashes on settlement handler for contract `{}`",
                key.name
            );
            let map = map.clone();
            self.settlements.insert(
                key,
                Rc::new(move |d, h, cx| {
                    let o2 = sub_settler(lens(d), h, cx)?;
                    map(d, o2)
                }),
            );
        }
        self
    }

    /// The arrival handler for `key`, if any.
    pub(crate) fn arrival(&self, key: &ContractKey) -> Option<ArrivalFn<D, O>> {
        self.arrivals.get(key).cloned()
    }

    /// The settlement handler for `key`, if any.
    pub(crate) fn settlement(&self, key: &ContractKey) -> Option<SettledFn<D, O>> {
        self.settlements.get(key).cloned()
    }

    /// Whether the role can follow the token into `key` (has an arrival handler).
    pub(crate) fn handles_arrival(&self, key: &ContractKey) -> bool {
        self.arrivals.contains_key(key)
    }

    /// Whether the role explicitly ignores `key` children.
    pub(crate) fn ignores(&self, key: &ContractKey) -> bool {
        self.ignored.contains(key)
    }
}

/// Map a sub-protocol action into the outer protocol, converting outcomes
/// through `map` (recursing into timeout fallbacks).
fn map_action<D, O2, O>(
    d: &mut D,
    action: Action<O2>,
    map: &dyn Fn(&mut D, O2) -> Result<O, ProtocolError>,
) -> Result<Action<O>, ProtocolError> {
    Ok(match action {
        Action::Send(b) => Action::Send(b),
        Action::SendFinal(b, o2) => Action::SendFinal(b, map(d, o2)?),
        Action::Wait => Action::Wait,
        Action::WaitWithTimeout { blocks, on_timeout } => Action::WaitWithTimeout {
            blocks,
            on_timeout: Box::new(map_action(d, *on_timeout, map)?),
        },
        Action::Finish(o2) => Action::Finish(map(d, o2)?),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::fund_fake;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Transaction, Txid};
    use mattrs_derive::{contract, ContractParams};

    #[derive(Debug, Clone, ContractParams)]
    pub struct PairParams {
        pub tag: i64,
    }

    // Two distinct contracts sharing the params type: they erase to the same
    // `StandardP2TR<PairParams>`, so only the name tells them apart.
    contract! {
        contract KeyA {
            params PairParams;
            clause noop {
                args { x: i64, }
                script |_p| ScriptBuf::from(vec![0x51u8]);
            }
            tree [noop];
        }
    }

    contract! {
        contract KeyB {
            params PairParams;
            clause noop {
                args { x: i64, }
                script |_p| ScriptBuf::from(vec![0x52u8]);
            }
            tree [noop];
        }
    }

    /// A chain that answers nothing (handlers under test never reach it).
    struct NoChain;
    impl ChainView for NoChain {
        fn broadcast(&self, _tx: &Transaction) -> Result<(), ProtocolError> {
            Err(ProtocolError::Other("no chain".into()))
        }
        fn find_spending_tx(
            &self,
            _outpoint: OutPoint,
        ) -> Result<Option<Transaction>, ProtocolError> {
            Ok(None)
        }
        fn height(&self) -> Result<u32, ProtocolError> {
            Ok(0)
        }
        fn confirmation_height(&self, _txid: Txid) -> Result<Option<u32>, ProtocolError> {
            Ok(None)
        }
    }

    #[test]
    fn contract_key_disambiguates_shared_type_ids() {
        assert_eq!(KeyA::kind_id(), KeyB::kind_id());
        assert_ne!(KeyA::kind(), KeyB::kind());
    }

    #[test]
    fn typed_handles_key_on_name_too() {
        let a = fund_fake(
            KeyA::new(PairParams { tag: 42 }).as_erased(),
            None,
            Amount::from_sat(1000),
            1,
        );
        assert_eq!(ContractKey::of_handle(&a), KeyA::kind());
        let typed: KeyAHandle = a.clone().try_into().expect("same contract");
        assert_eq!(typed.params().expect("decodes").tag, 42);
        // A same-TypeId instance of the *other* contract must not convert.
        assert!(KeyBHandle::try_from(a).is_err());
    }

    #[test]
    fn embed_maps_outcomes_through_the_lens() {
        struct Outer {
            sub: u32,
        }
        let sub: Role<u32, i64> = Role::new().on::<KeyB, _>(|d, _h, _cx| {
            *d += 1;
            Ok(Action::WaitWithTimeout {
                blocks: 5,
                on_timeout: Box::new(Action::Finish(7)),
            })
        });
        let outer: Role<Outer, String> = Role::new()
            .on::<KeyA, _>(|_d, _h, _cx| Ok(Action::Wait))
            .embed(sub, |d: &mut Outer| &mut d.sub, |_d, o| Ok(format!("sub:{o}")));

        assert!(outer.handles_arrival(&KeyA::kind()));
        assert!(outer.handles_arrival(&KeyB::kind()));

        let b = fund_fake(
            KeyB::new(PairParams { tag: 0 }).as_erased(),
            None,
            Amount::from_sat(1000),
            2,
        );
        let mut data = Outer { sub: 0 };
        let cx = StepCtx {
            parent: None,
            chain: &NoChain,
        };
        let action = outer.arrival(&KeyB::kind()).expect("mounted")(&mut data, b, &cx)
            .expect("handler runs");
        // The sub-handler ran on the lensed data, and its outcome — nested
        // inside the timeout fallback — was mapped into the outer type.
        assert_eq!(data.sub, 1);
        match action {
            Action::WaitWithTimeout { blocks, on_timeout } => {
                assert_eq!(blocks, 5);
                match *on_timeout {
                    Action::Finish(o) => assert_eq!(o, "sub:7"),
                    _ => panic!("timeout fallback should be the mapped Finish"),
                }
            }
            _ => panic!("action shape should be preserved"),
        }
    }

    #[test]
    #[should_panic(expected = "already has an arrival handler")]
    fn duplicate_arrival_handlers_panic() {
        let _ = Role::<(), ()>::new()
            .on::<KeyA, _>(|_, _, _| Ok(Action::Wait))
            .on::<KeyA, _>(|_, _, _| Ok(Action::Wait));
    }

    #[test]
    #[should_panic(expected = "already has an arrival handler")]
    fn ignoring_a_handled_contract_panics() {
        let _ = Role::<(), ()>::new()
            .on::<KeyA, _>(|_, _, _| Ok(Action::Wait))
            .ignore::<KeyA>();
    }

    #[test]
    #[should_panic(expected = "already ignores")]
    fn handling_an_ignored_contract_panics() {
        let _ = Role::<(), ()>::new()
            .ignore::<KeyA>()
            .on::<KeyA, _>(|_, _, _| Ok(Action::Wait));
    }

    #[test]
    fn embed_merges_ignores() {
        let sub: Role<(), ()> = Role::new().ignore::<KeyB>();
        let outer: Role<(), ()> = Role::new()
            .on::<KeyA, _>(|_, _, _| Ok(Action::Wait))
            .embed(sub, |d: &mut ()| d, |_d, o| Ok(o));
        assert!(outer.ignores(&KeyB::kind()));
        assert!(!outer.ignores(&KeyA::kind()));
    }

    #[test]
    #[should_panic(expected = "which this role ignores")]
    fn embedded_handler_for_an_ignored_contract_panics() {
        let sub: Role<(), ()> = Role::new().on::<KeyB, _>(|_, _, _| Ok(Action::Wait));
        let _ = Role::<(), ()>::new()
            .ignore::<KeyB>()
            .embed(sub, |d: &mut ()| d, |_d, o| Ok(o));
    }

    #[test]
    #[should_panic(expected = "which this role handles")]
    fn embedded_ignore_of_a_handled_contract_panics() {
        let sub: Role<(), ()> = Role::new().ignore::<KeyA>();
        let _ = Role::<(), ()>::new()
            .on::<KeyA, _>(|_, _, _| Ok(Action::Wait))
            .embed(sub, |d: &mut ()| d, |_d, o| Ok(o));
    }
}

//! In-memory runtime state store for the the gateway. Holds
//! resolved views of binds, listeners, routes, and backends;
//! accepts per-entity updates; stashes objects with unmet references and
//! re-evaluates them when dependencies land.

pub mod active;
pub mod error;
pub mod event;
pub mod key;
pub mod store;

pub use active::{
    ActiveBackend, ActiveBackendRef, ActiveBind, ActiveHttpListener, ActiveHttpRoute,
};
pub use error::{ApplyReport, StoreError};
pub use event::BindEvent;
pub use key::{BackendKey, BindKey, ListenerKey, RegisteredKeys, RouteKey};
pub use store::{Store, StoreRead};

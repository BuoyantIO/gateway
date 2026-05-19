use crate::key::BindKey;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindEvent {
    Added(BindKey),
    Updated(BindKey),
    Removed(BindKey),
}

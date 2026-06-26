use std::collections::HashSet;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BindKey(pub String);

impl BindKey {
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }
}

impl fmt::Display for BindKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ListenerKey {
    pub bind: BindKey,
    pub name: String,
}

impl ListenerKey {
    pub fn new(bind: BindKey, name: impl Into<String>) -> Self {
        Self {
            bind,
            name: name.into(),
        }
    }
}

impl fmt::Display for ListenerKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.bind, self.name)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RouteKey {
    pub listener: ListenerKey,
    pub name: String,
}

impl RouteKey {
    pub fn new(listener: ListenerKey, name: impl Into<String>) -> Self {
        Self {
            listener,
            name: name.into(),
        }
    }
}

impl fmt::Display for RouteKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.listener, self.name)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BackendKey(pub String);

impl BackendKey {
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }
}

impl fmt::Display for BackendKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SecretKey(pub String);

impl SecretKey {
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }
}

impl fmt::Display for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Keep-set for [`crate::Store::retain`].
#[derive(Debug, Default, Clone)]
pub struct RegisteredKeys {
    pub binds: HashSet<BindKey>,
    pub listeners: HashSet<ListenerKey>,
    pub routes: HashSet<RouteKey>,
    pub backends: HashSet<BackendKey>,
    pub secrets: HashSet<SecretKey>,
}

//! Plugin name → builder lookup.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::sync::Arc;

use super::ExtensionBuilder;

/// Maps plugin names to builders. Populated at startup; a duplicate
/// name is a configuration bug the caller treats as fatal.
#[derive(Default)]
pub struct Registry {
    builders: HashMap<String, Arc<dyn ExtensionBuilder>>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a builder under `name`.
    ///
    /// # Errors
    /// [`RegistryError::Duplicate`] when the name is taken.
    pub fn register(
        &mut self,
        name: &str,
        builder: Arc<dyn ExtensionBuilder>,
    ) -> Result<(), RegistryError> {
        match self.builders.entry(name.to_owned()) {
            Entry::Occupied(_) => Err(RegistryError::Duplicate(name.to_owned())),
            Entry::Vacant(slot) => {
                slot.insert(builder);
                Ok(())
            }
        }
    }

    pub fn get(&self, name: &str) -> Option<Arc<dyn ExtensionBuilder>> {
        self.builders.get(name).cloned()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("extension plugin `{0}` is already registered")]
    Duplicate(String),
}

#[cfg(test)]
mod tests {
    use super::super::{BodyMode, Extension};
    use super::*;

    struct NoopBuilder;

    impl ExtensionBuilder for NoopBuilder {
        fn build(&self) -> Box<dyn Extension> {
            unreachable!("registry tests never build instances")
        }
    }

    #[test]
    fn register_and_get() {
        let mut registry = Registry::new();
        registry.register("noop", Arc::new(NoopBuilder)).unwrap();

        let builder = registry.get("noop").expect("registered");
        assert_eq!(builder.declares().request_body, BodyMode::None);
        assert!(registry.get("other").is_none());
    }

    #[test]
    fn duplicate_name_errors() {
        let mut registry = Registry::new();
        registry.register("noop", Arc::new(NoopBuilder)).unwrap();

        let err = registry
            .register("noop", Arc::new(NoopBuilder))
            .unwrap_err();
        assert!(matches!(err, RegistryError::Duplicate(name) if name == "noop"));
    }
}

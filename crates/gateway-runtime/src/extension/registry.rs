//! Extension class lookup and `Extension` object configuration.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::sync::Arc;

use gateway_config::extension::{ConfigValue, Extension, FailureMode, RequestBodyLimit};

use super::{BodyMode, Declarations, Error, ExtensionBuilder};

/// Code that turns an `Extension` object's opaque config into a
/// configured builder.
pub trait ExtensionClass: Send + Sync {
    /// Build one configured builder from an `Extension` object's
    /// config. Deserialization, validation, and preparation happen
    /// here, once per object; `build()` on the returned builder is a
    /// constructor.
    ///
    /// # Errors
    /// A config the class does not understand.
    fn configure(&self, config: &ConfigValue) -> Result<Arc<dyn ExtensionBuilder>, Error>;
}

/// Maps class names to classes. Populated at startup; a duplicate
/// name is a configuration bug the caller treats as fatal.
#[derive(Default)]
pub struct Registry {
    classes: HashMap<String, Arc<dyn ExtensionClass>>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a class under `name`.
    ///
    /// # Errors
    /// [`RegistryError::Duplicate`] when the name is taken.
    pub fn register(
        &mut self,
        name: &str,
        class: Arc<dyn ExtensionClass>,
    ) -> Result<(), RegistryError> {
        match self.classes.entry(name.to_owned()) {
            Entry::Occupied(_) => Err(RegistryError::Duplicate(name.to_owned())),
            Entry::Vacant(slot) => {
                slot.insert(class);
                Ok(())
            }
        }
    }

    /// Registers a pre-built builder under `name`, as a class that
    /// ignores config. The bridge for code-registered extensions
    /// while `ExtensionRef` names classes directly.
    ///
    /// # Errors
    /// [`RegistryError::Duplicate`] when the name is taken.
    pub fn register_builder(
        &mut self,
        name: &str,
        builder: Arc<dyn ExtensionBuilder>,
    ) -> Result<(), RegistryError> {
        self.register(name, Arc::new(PreConfigured(builder)))
    }

    pub fn get(&self, name: &str) -> Option<Arc<dyn ExtensionClass>> {
        self.classes.get(name).cloned()
    }

    /// Configure one `Extension` object: resolve its class, hand it
    /// the config, and hold the declarations to the object's limits.
    ///
    /// # Errors
    /// The class is not registered, the class rejected the config,
    /// or the builder declares more than the object grants.
    pub fn configure(&self, ext: &Extension) -> Result<ConfiguredExtension, ConfigureError> {
        let class = self
            .get(&ext.class)
            .ok_or_else(|| ConfigureError::UnknownClass(ext.class.clone()))?;
        let builder = class
            .configure(&ext.config)
            .map_err(|e| ConfigureError::Rejected {
                class: ext.class.clone(),
                detail: e.to_string(),
            })?;
        let decl = builder.declares();
        if let Some(ceiling) = ext.limits.request_body
            && limit_of(decl.request_body) > ceiling
        {
            return Err(ConfigureError::OverLimit {
                name: ext.name.clone(),
                declared: decl.request_body,
                ceiling,
            });
        }
        Ok(ConfiguredExtension {
            name: ext.name.clone(),
            builder,
            failure_mode: ext.failure_mode,
            decl,
            max_buffer_bytes: ext.limits.max_buffer_bytes,
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("extension class `{0}` is already registered")]
    Duplicate(String),
}

/// A class that ignores config and hands out one pre-built builder,
/// shared by every caller.
pub struct PreConfigured(pub Arc<dyn ExtensionBuilder>);

impl ExtensionClass for PreConfigured {
    fn configure(&self, _config: &ConfigValue) -> Result<Arc<dyn ExtensionBuilder>, Error> {
        Ok(Arc::clone(&self.0))
    }
}

/// One `Extension` object, configured: the builder plus the object's
/// policy, ready to build per-request instances.
pub struct ConfiguredExtension {
    pub name: String,
    pub builder: Arc<dyn ExtensionBuilder>,
    pub failure_mode: FailureMode,
    /// The builder's declarations, already held to the object's
    /// limits.
    pub decl: Declarations,
    pub max_buffer_bytes: Option<u64>,
}

// Hand-written: the builder is not `Debug`.
impl std::fmt::Debug for ConfiguredExtension {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfiguredExtension")
            .field("name", &self.name)
            .field("failure_mode", &self.failure_mode)
            .field("decl", &self.decl)
            .field("max_buffer_bytes", &self.max_buffer_bytes)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigureError {
    #[error("no extension class registered under `{0}`")]
    UnknownClass(String),
    #[error("class `{class}` rejected the config: {detail}")]
    Rejected { class: String, detail: String },
    #[error("`{name}` declares request body {declared:?} over the {ceiling:?} ceiling")]
    OverLimit {
        name: String,
        declared: BodyMode,
        ceiling: RequestBodyLimit,
    },
}

/// The ceiling bucket a declared mode occupies.
fn limit_of(mode: BodyMode) -> RequestBodyLimit {
    match mode {
        BodyMode::None => RequestBodyLimit::None,
        BodyMode::Stream => RequestBodyLimit::Stream,
        BodyMode::Buffer => RequestBodyLimit::Buffer,
    }
}

#[cfg(test)]
mod tests {
    use super::super::Extension as ExtensionInstance;
    use super::*;

    use gateway_config::extension::Limits;

    /// Builds a fresh builder per configure call and rejects any
    /// non-null config.
    struct StrictClass {
        declares: Declarations,
    }

    impl ExtensionClass for StrictClass {
        fn configure(&self, config: &ConfigValue) -> Result<Arc<dyn ExtensionBuilder>, Error> {
            if !config.is_null() {
                return Err("unknown config".into());
            }
            Ok(Arc::new(FixedBuilder {
                declares: self.declares,
            }))
        }
    }

    struct FixedBuilder {
        declares: Declarations,
    }

    impl ExtensionBuilder for FixedBuilder {
        fn declares(&self) -> Declarations {
            self.declares
        }

        fn build(&self) -> Box<dyn ExtensionInstance> {
            unreachable!("registry tests never build instances")
        }
    }

    fn object(name: &str, class: &str, limits: Limits) -> Extension {
        Extension {
            name: name.into(),
            class: class.into(),
            failure_mode: FailureMode::default(),
            limits,
            config: ConfigValue::Null,
        }
    }

    fn streaming_registry() -> Registry {
        let mut registry = Registry::new();
        registry
            .register(
                "streamer",
                Arc::new(StrictClass {
                    declares: Declarations {
                        request_body: BodyMode::Stream,
                        ..Default::default()
                    },
                }),
            )
            .unwrap();
        registry
    }

    #[test]
    fn duplicate_name_errors() {
        let mut registry = streaming_registry();
        let err = registry
            .register_builder(
                "streamer",
                Arc::new(FixedBuilder {
                    declares: Declarations::default(),
                }),
            )
            .unwrap_err();
        assert!(matches!(err, RegistryError::Duplicate(name) if name == "streamer"));
    }

    #[test]
    fn one_class_configures_independent_builders() {
        let registry = streaming_registry();
        let obj = object("a", "streamer", Limits::default());
        let one = registry.configure(&obj).unwrap();
        let two = registry.configure(&obj).unwrap();
        assert!(!Arc::ptr_eq(&one.builder, &two.builder));
        assert_eq!(one.decl.request_body, BodyMode::Stream);
    }

    #[test]
    fn unknown_class_errors() {
        let registry = streaming_registry();
        let err = registry
            .configure(&object("a", "absent", Limits::default()))
            .unwrap_err();
        assert!(matches!(err, ConfigureError::UnknownClass(c) if c == "absent"));
    }

    #[test]
    fn rejected_config_names_the_class() {
        let registry = streaming_registry();
        let mut obj = object("a", "streamer", Limits::default());
        obj.config = ConfigValue::from("bogus");
        let err = registry.configure(&obj).unwrap_err();
        assert!(matches!(err, ConfigureError::Rejected { class, detail }
                if class == "streamer" && detail.contains("unknown config")));
    }

    #[test]
    fn declaration_over_the_ceiling_errors() {
        let registry = streaming_registry();
        let over = object(
            "a",
            "streamer",
            Limits {
                request_body: Some(RequestBodyLimit::None),
                max_buffer_bytes: None,
            },
        );
        let err = registry.configure(&over).unwrap_err();
        assert!(matches!(err, ConfigureError::OverLimit { .. }));

        // At the ceiling is granted, and the caps ride along.
        let at = object(
            "a",
            "streamer",
            Limits {
                request_body: Some(RequestBodyLimit::Stream),
                max_buffer_bytes: None,
            },
        );
        let configured = registry.configure(&at).unwrap();
        assert_eq!(configured.decl.request_body, BodyMode::Stream);
        assert!(configured.max_buffer_bytes.is_none());
    }
}

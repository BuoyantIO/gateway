//! The inline-filter funnel: reserved class names for the built-in
//! extensions and the mapping from a route's typed filter config to
//! the opaque value its class deserializes. The classes themselves
//! live in `gateway-extension-impls`.

use gateway_config::extension::{ConfigValue, to_value};
use gateway_config::filter::HttpFilter as ConfigFilter;

/// Reserved class names for the built-ins.
pub const REQUEST_HEADER_MODIFIER: &str = "request_header_modifier";
pub const RESPONSE_HEADER_MODIFIER: &str = "response_header_modifier";
pub const REQUEST_REDIRECT: &str = "request_redirect";

#[derive(Debug, thiserror::Error)]
pub enum FilterError {
    #[error("invalid header name `{0}`")]
    InvalidHeaderName(String),
    #[error("invalid header value for `{0}`")]
    InvalidHeaderValue(String),
    #[error("`{class}` config cannot serialize: {detail}")]
    ConfigSerialize { class: String, detail: String },
}

/// The class name and config for one inline filter — the funnel
/// their construction goes through: the typed config serializes into
/// the opaque value its reserved class deserializes. Refs do not
/// pass here; they resolve through the route's `Extension` objects.
///
/// # Errors
/// A config the value format cannot represent.
pub fn class_and_config(cfg: &ConfigFilter) -> Result<(&str, ConfigValue), FilterError> {
    let (class, config) = match cfg {
        ConfigFilter::RequestHeaderModifier {
            request_headers, ..
        } => (REQUEST_HEADER_MODIFIER, to_value(request_headers)),
        ConfigFilter::ResponseHeaderModifier {
            response_headers, ..
        } => (RESPONSE_HEADER_MODIFIER, to_value(response_headers)),
        ConfigFilter::RequestRedirect { redirect, .. } => (REQUEST_REDIRECT, to_value(redirect)),
        ConfigFilter::ExtensionRef { .. } => {
            unreachable!("refs resolve through Extension objects, not the inline funnel")
        }
    };
    let config = config.map_err(|e| FilterError::ConfigSerialize {
        class: class.to_owned(),
        detail: e.to_string(),
    })?;
    Ok((class, config))
}

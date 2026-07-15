//! Single integration-test binary for the e2e suite. One binary means
//! libtest's thread pool parallelizes across every test in every
//! module — cargo runs separate test binaries sequentially, so
//! per-file binaries would serialize between files no matter the
//! thread count.

mod backend_protocol;
mod endpoints;
mod filters;
mod matches;
mod provisioner;
mod redirect;
mod routing;
mod status;
mod tls;

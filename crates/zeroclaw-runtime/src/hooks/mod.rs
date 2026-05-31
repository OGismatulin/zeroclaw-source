pub mod builtin;
mod prompt_trace;
mod runner;
mod traits;

pub use prompt_trace::PromptTraceHook;
pub use runner::HookRunner;
// HookHandler and HookResult are part of the crate's public hook API surface.
// They may appear unused internally but are intentionally re-exported for
// external integrations and future plugin authors.
#[allow(unused_imports)]
pub use traits::{HookHandler, HookResult};

//! rsdns pipeline stages.
//!
//! The query pipeline is a **fixed** sequence of stages (no plugin
//! registry / dynamic chain):
//!
//! ```text
//! logs → hosts → groups → cache → rules
//! ```
//!
//! Each module owns one stage, its configuration and its metrics.  Stages
//! are plain modules exposing an `init`/`handle` function — not trait
//! objects.  `groups` is a fixed pre-stage driven by the top-level
//! `groups[]` array; the upstream provider lives in `crate::upstream`
//! and is injected into the server (not a pipeline stage).

pub mod cache;
pub mod groups;
pub mod hosts;
#[cfg(feature = "jemalloc")]
pub mod jemalloc;
pub mod logs;
pub mod rules;
pub mod speed;
pub mod ui;
pub mod util;

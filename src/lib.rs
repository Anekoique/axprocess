//! Process Management

#![no_std]

extern crate alloc;

mod process;
mod process_group;
mod session;
mod thread;

/// A process ID, also used as session ID, process group ID, and thread ID.
pub type Pid = u32;

pub use process::*;
pub use process_group::*;
pub use session::*;
pub use thread::*;

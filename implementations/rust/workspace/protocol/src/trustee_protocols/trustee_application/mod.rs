//! Trustee actor implementation.
//!
//! This module provides a thin wrapper around the protocol_logic module that:
//! - Maintains a local copy of the bulletin board (full TrusteeMsg objects)
//! - Converts TrusteeMsg to summary Message objects for protocol logic
//! - Uses Ascent inference to determine what actions to take
//! - Executes actions on real cryptographic data
//! - Produces TrusteeMsg objects to send to the TAS

pub(crate) mod ascent_logic;
pub(crate) mod handlers;
pub mod top_level_actor;

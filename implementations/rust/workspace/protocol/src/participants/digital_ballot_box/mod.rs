// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! Digital Ballot Box (DBB) implementation.
//!
//! The Digital Ballot Box is responsible for:
//! - Processing ballot submissions from voters, including validating the
//!   voter authorization tokens (signed by the EAS) embedded in them
//! - Processing ballot casting requests
//! - Forwarding ballot check requests between BCA and VA
//! - Maintaining the public bulletin board
//!
//! The DBB holds no persistent state of its own beyond the bulletin board:
//! every check it performs is answered by querying the bulletin board, which
//! is the sole source of truth for the election.
//!
//! The DBB handles concurrent sessions using a state machine approach,
//! with separate sub-actors for each protocol type.

/// Bulletin-board data structures and helpers.
pub mod bulletin_board;
/// DBB sub-actor implementations.
pub mod sub_actors;
/// Top-level DBB actor implementation.
pub mod top_level_actor;

// Re-export main types for convenience
pub use crate::bulletins::BulletinTypeRegistry;
pub use bulletin_board::{BulletinBoard, InMemoryBulletinBoard};
pub use top_level_actor::{
    ActorInput, ActorOutput, Command, DBBIncomingMessage, DBBOutgoingMessage,
    DigitalBallotBoxActor, SessionInfo, SessionType,
};

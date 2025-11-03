// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! Digital Ballot Box (DBB) implementation.
//!
//! The Digital Ballot Box is responsible for:
//! - Receiving and validating voter authorizations from the EAS
//! - Processing ballot submissions from voters
//! - Processing ballot casting requests
//! - Forwarding ballot check requests between BCA and VA
//! - Maintaining the public bulletin board
//! - Storing all persistent state
//!
//! The DBB handles concurrent sessions using a state machine approach,
//! with separate sub-actors for each protocol type.

pub mod bulletin_board;
pub mod storage;
pub mod sub_actors;
pub mod top_level_actor;

// Re-export main types for convenience
pub use bulletin_board::{BulletinBoard, BulletinType, InMemoryBulletinBoard};
pub use storage::{DBBStorage, InMemoryStorage};
pub use top_level_actor::{
    ActorInput, ActorOutput, Command, DBBIncomingMessage, DBBOutgoingMessage,
    DigitalBallotBoxActor, EASMessage, SessionInfo, SessionType,
};

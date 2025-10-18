//! The core library for the VoteSecure project.
//!
//! This library provides a state machine implementation of the e-voting protocol
//! for the on-device Voting Application. It is designed to be integrated into
//! a host application that will provide the networking and user interface layers.
//!
//! The primary entry point is the `TopLevelActor`, which manages the state
//! for all subprotocols.

// --- Public Modules ---
// These modules contain the data structures that are passed to and from the actor.

// Disable unused imports warning as the crypto utils are used by the Vserializable macro but clippy can't figure that out.
#[allow(unused_imports)]
use ::crypto::utils;

/// Contains messages and structure relevant to interacting with the Authentication Service (AS).
pub mod auth_service;
/// Contains all Public Bulletin Board entry structures.
pub mod bulletins;
/// Contains common cryptographic data structures.
pub mod crypto;
/// Contains election data structures and ballot representations.
pub mod elections;
/// Contains all network message structures, unified under the `ProtocolMessage` enum.
pub mod messages;
/// Contains the protocol participant actor implementations.
pub mod participants;

// --- Public API Exports ---
// Re-export the most important types for convenient access by the library user.

pub use elections::Ballot;

pub use participants::voting_application::{
    sub_actors::{
        authentication::AuthenticationInput, casting::CastingInput, checking::CheckingInput,
        submission::SubmissionInput,
    },
    top_level_actor::{
        // The unified input type for the actor.
        ActorInput,
        // Specific success/outcome structures for the application to handle.
        BallotCastingSuccess,
        BallotCheckOutcome,
        BallotSubmissionSuccess,
        // The enums that make up the `ActorInput`.
        Command,
        // The input type for subprotocols
        SubprotocolInput,
        // The unified result type from the actor - now it's SubprotocolOutput!
        SubprotocolOutput,
        // The main actor struct.
        TopLevelActor,
        VoterAuthenticationSuccess,
    },
};

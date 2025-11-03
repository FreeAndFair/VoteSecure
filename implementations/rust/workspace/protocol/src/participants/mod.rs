// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! This module contains all Internet-facing protocol implementations.

/// Declares the Ballot Check Application (BCA) submodule.
pub mod ballot_check_application;

/// Declares the Election Administration Server (EAS) submodule.
pub mod election_admin_server;

/// Declares the Digital Ballot Box (DBB) submodule.
pub mod digital_ballot_box;

/// Declares the Voting Application (VA) submodule.
pub mod voting_application;

/// Basic integration tests for Internet-facing protocol actors.
#[cfg(test)]
mod integration_tests_basic;

/// Stateright model-based integration tests for Internet-facing protocol actors.
#[cfg(test)]
mod integration_tests;

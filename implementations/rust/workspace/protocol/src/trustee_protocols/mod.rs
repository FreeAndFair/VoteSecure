// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! This module contains all trustee-related protocol implementations,
//! including the trustee application and the trustee administration server.

/// The trustee administration server.
pub mod trustee_administration_server;

/// The trustee application.
pub mod trustee_application;

/// The trustee cryptography library (internal).
pub(crate) mod trustee_cryptography;

/// The trustee message types
pub mod trustee_messages;

#[cfg(test)]
/// Basic integration tests for the trustee protocols.
mod integration_tests_basic;

#[cfg(test)]
/// Stateright model checking integration tests for the trustee protocols.
mod integration_tests;

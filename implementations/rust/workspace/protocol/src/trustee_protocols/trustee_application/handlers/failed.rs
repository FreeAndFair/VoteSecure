// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! This file contains the state handler for the `Failed` state.

use super::*;

impl TrusteeStateHandler for Failed {
    /// Reject all new board updates, because the trustee is
    /// in the failed state.
    fn handle_message_bb_update(
        &self,
        _input: &TrusteeBBUpdateMsg,
        actor: &mut TrusteeActor,
    ) -> (
        Option<TrusteeState>,
        Option<TrusteeOutput>,
        Option<TrusteeMsg>,
    ) {
        (
            None,
            Some(TrusteeOutput::Failed(actor.failure_data(
                "Trustee has failed, cannot process board updates".to_string(),
            ))),
            None,
        )
    }

    /// Always return (None, None); once the trustee is in the failed
    /// state, it stays there forever.
    fn determine_next_state_and_output(
        &self,
        _actor: &TrusteeActor,
    ) -> (Option<TrusteeState>, Option<TrusteeOutput>) {
        (None, None)
    }
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! This file contains the TAS state handler for the `Failed`
//! state. It handles only one type of message (`Stop`); any
//! other message type is rejected in this state.

use super::*;

impl TASStateHandler for Failed {
    fn handle_stop(
        &self,
        _input: &Stop,
        actor: &mut TASActor,
    ) -> (
        Option<TASState>,
        Option<TASOutput>,
        Option<TrusteeBBUpdateMsg>,
    ) {
        // Cannot stop when we're idle or failed, since we're already stopped.
        (
            None,
            Some(TASOutput::Failed(
                actor.failure_data("TAS is already stopped.".to_string()),
            )),
            None,
        )
    }
}

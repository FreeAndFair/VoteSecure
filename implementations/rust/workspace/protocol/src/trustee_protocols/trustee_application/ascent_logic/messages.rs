// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! Messages for the protocol

use super::types::*;
use strum::Display;

#[derive(Clone, PartialEq, Eq, Hash, Debug, Display, Ord, PartialOrd)]
pub(crate) enum Message {
    ConfigurationValid(CfgHash, TrusteeCount, TrusteeCount, TrusteeIndex),
    Shares(CfgHash, TrusteeSharesHash, Sender),
    PublicKey(CfgHash, PublicKeyHash, Sender),
    Ballots(CfgHash, PublicKeyHash, CiphertextsHash, Vec<TrusteeIndex>),
    // cfg hash, pk hash, mix input hash, mix output hash, sender
    Mix(
        CfgHash,
        PublicKeyHash,
        CiphertextsHash,
        CiphertextsHash,
        TrusteeIndex,
    ),
    // cfg hash, pk hash, mix input hash, mix output hash, sender
    MixSignature(
        CfgHash,
        PublicKeyHash,
        CiphertextsHash,
        CiphertextsHash,
        TrusteeIndex,
    ),
    PartialDecryptions(
        CfgHash,
        PublicKeyHash,
        CiphertextsHash,
        PartialDecryptionsHash,
        TrusteeIndex,
    ),
    Plaintexts(
        CfgHash,
        PublicKeyHash,
        CiphertextsHash,
        PlaintextsHash,
        TrusteeIndex,
    ),
}
impl Message {
    // Every message has a unique "slot". This function checks to ensure
    // that no two messages collide.
    pub(crate) fn collides(&self, other: &Message) -> bool {
        // For the purposes of ascent logic, two messages instances for
        // which equality holds are considered to be the same message, and
        // do not collide.
        if self == other {
            return false;
        }
        // If the variants differ, they cannot collide.
        if std::mem::discriminant(self) != std::mem::discriminant(other) {
            return false;
        }

        match (self, other) {
            (
                Message::ConfigurationValid(_, _, _, sender1),
                Message::ConfigurationValid(_, _, _, sender2),
            ) => sender1 == sender2,
            (Message::Shares(_, _shares1, sender1), Message::Shares(_, _shares2, sender2)) => {
                sender1 == sender2
            }
            (
                Message::PublicKey(_, _shares1, sender1),
                Message::PublicKey(_, _shares2, sender2),
            ) => sender1 == sender2,
            (Message::Ballots(_, _, _, _), Message::Ballots(_, _, _, _)) => true,
            (Message::Mix(_, _, _, _, sender1), Message::Mix(_, _, _, _, sender2)) => {
                sender1 == sender2
            }
            (
                Message::MixSignature(_, _, in_ciphertexts1, out_ciphertexts1, sender1),
                Message::MixSignature(_, _, in_ciphertexts2, out_ciphertexts2, sender2),
            ) => {
                sender1 == sender2
                    && ((in_ciphertexts1 == in_ciphertexts2)
                        || (out_ciphertexts1 == out_ciphertexts2))
            }
            (
                Message::PartialDecryptions(_, _, _, _, sender1),
                Message::PartialDecryptions(_, _, _, _, sender2),
            ) => sender1 == sender2,
            (
                Message::Plaintexts(_, _, _, _, sender1),
                Message::Plaintexts(_, _, _, _, sender2),
            ) => sender1 == sender2,
            _ => false,
        }
    }

    pub(crate) fn get_cfg(&self) -> CfgHash {
        match self {
            Message::ConfigurationValid(cfg_hash, _, _, _) => *cfg_hash,
            Message::Shares(cfg_hash, _, _) => *cfg_hash,
            Message::PublicKey(cfg_hash, _, _) => *cfg_hash,

            Message::Ballots(cfg_hash, _, _, _) => *cfg_hash,
            Message::Mix(cfg_hash, _, _, _, _) => *cfg_hash,

            Message::MixSignature(cfg_hash, _, _, _, _) => *cfg_hash,
            Message::PartialDecryptions(cfg_hash, _, _, _, _) => *cfg_hash,
            Message::Plaintexts(cfg_hash, _, _, _, _) => *cfg_hash,
        }
    }
}

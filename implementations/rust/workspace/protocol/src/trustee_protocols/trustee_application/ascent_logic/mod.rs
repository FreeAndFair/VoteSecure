/*
 * Root module for the stateright protocol model
 *
 * @author David Ruescas (david@sequentech.io)\
 * @copyright Free & Fair. 2025\
 * @version 0.1
 */

#![allow(dead_code)]
pub mod decrypt;
pub mod dkg;
pub mod messages;
pub mod mix;
pub mod protocol;
pub mod utils;

use std::array;
use std::fmt::Formatter;
use std::marker::PhantomData;

use self::messages::Message;
use self::utils::AccumulatorSet;
use crate::crypto::CryptoHash;

use crypto::context::Context;

// Re-export Message as AscentMsg for the top-level actor
pub(crate) use self::messages::Message as AscentMsg;

/// This will be moved once the subprotocol stateright
/// tests are moved into their own modules
const HASH_SIZE: usize = 64;

/// All types used in ascent logic implement std::hash::Hash
/// so that they can be used in stateright relations. However
/// the computations of _input_ hash values are carried
/// out by the CryptoContext hasher. Stateright will
/// later compute its own hashes internally, but these are
/// not used outside of stateright.
pub(crate) mod types {
    use super::AccumulatorSet;
    use super::CryptoHash;

    pub(crate) type CfgHash = CryptoHash;
    pub(crate) type TrusteeSharesHash = CryptoHash;
    pub(crate) type PublicKeyHash = CryptoHash;
    pub(crate) type CiphertextsHash = CryptoHash;
    pub(crate) type SharesHashesAcc = AccumulatorSet<TrusteeSharesHash>;
    pub(crate) type SharesHashes = Vec<TrusteeSharesHash>;
    pub(crate) type Sender = TrusteeIndex;
    pub(crate) type TrusteeIndex = usize;
    pub(crate) type TrusteeCount = usize;
    pub(crate) type PartialDecryptionsHash = CryptoHash;
    pub(crate) type PartialDecryptionsHashesAcc = AccumulatorSet<PartialDecryptionsHash>;
    pub(crate) type PartialDecryptionsHashes = Vec<PartialDecryptionsHash>;
    pub(crate) type PlaintextsHash = CryptoHash;
}
use types::*;

#[derive(Clone, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub(crate) enum Action {
    ComputeShares(CfgHash, TrusteeIndex),
    ComputePublicKey(CfgHash, SharesHashes, TrusteeIndex),
    ComputeMix(CfgHash, PublicKeyHash, CiphertextsHash, TrusteeIndex),
    SignMix(
        CfgHash,
        PublicKeyHash,
        CiphertextsHash,
        CiphertextsHash,
        TrusteeIndex,
    ),
    ComputePartialDecryptions(CfgHash, PublicKeyHash, CiphertextsHash, TrusteeIndex),
    ComputePlaintexts(
        CfgHash,
        PublicKeyHash,
        CiphertextsHash,
        PartialDecryptionsHashes,
        TrusteeIndex,
    ),
    ComputeBallots(CfgHash, PublicKeyHash),
}

ascent::ascent_source! { prelude:
    relation error(String);
    relation message(Message);
    relation active(TrusteeIndex);

    error(format!("duplicate message {:?}, {:?}", m1, m2)) <--
        message(m1),
        message(m2),
        if m1.collides(m2);

    // this message comes from the setup phase
    relation configuration_valid(CfgHash, TrusteeCount, TrusteeCount, TrusteeIndex);
    configuration_valid(cfg_hash, threshold, trustee_count, self_index) <--
        message(m),
        if let Message::ConfigurationValid(cfg_hash, threshold, trustee_count, self_index) = m;

    error(format!("message cfg does not match context {:?}", m1)) <--
        message(m1),
        configuration_valid(cfg_hash, _, _, _),
        if m1.get_cfg() != *cfg_hash;


    relation action(Action);
}

#[derive(Clone, Hash, PartialEq)]
pub(crate) struct HashBoard<C: Context, const W: usize, const T: usize, const P: usize> {
    pub(crate) messages: Vec<Message>,
    pub(crate) cfg_hash: CfgHash,
    pub(crate) pk_hash: PublicKeyHash,
    pub(crate) ballots_hash: CiphertextsHash,
    pub(crate) mix_hashes: [CiphertextsHash; T],
    pub(crate) mixing_trustees: [TrusteeIndex; T],
    phantom_c: PhantomData<C>,
}
impl<C: Context, const W: usize, const T: usize, const P: usize> HashBoard<C, W, T, P> {
    pub(crate) fn new(cfg_hash: CfgHash) -> Self {
        let messages: [Message; P] =
            array::from_fn(|i| Message::ConfigurationValid(cfg_hash, T, P, i + 1));
        let messages = messages.to_vec();
        let pk_hash = self::utils::empty_hash();
        let ballots_hash = self::utils::empty_hash();
        let mix_hashes = [self::utils::empty_hash(); T];
        let mixing_trustees = [0; T];

        Self {
            messages,
            cfg_hash,
            pk_hash,
            ballots_hash,
            mix_hashes,
            mixing_trustees,
            phantom_c: PhantomData,
        }
    }

    pub(crate) fn add_pk(&mut self, pk_hash: PublicKeyHash, sender: TrusteeIndex) {
        let message = Message::PublicKey(self.cfg_hash, pk_hash, sender + 1);
        self.pk_hash = pk_hash;
        self.messages.push(message);
    }

    pub(crate) fn add_ballots(
        &mut self,
        ballots_hash: CiphertextsHash,
        trustees: [TrusteeIndex; T],
    ) {
        let pk_hash = self.pk_hash;
        let message = Message::Ballots(self.cfg_hash, pk_hash, ballots_hash, trustees.to_vec());
        self.mixing_trustees = trustees;
        self.ballots_hash = ballots_hash;
        self.messages.push(message);
    }

    pub(crate) fn add_mix(
        &mut self,
        input_hash: CiphertextsHash,
        mix_hash: CiphertextsHash,
        sender: TrusteeIndex,
    ) {
        let sender = sender + 1;
        let message = Message::Mix(self.cfg_hash, self.pk_hash, input_hash, mix_hash, sender);
        self.mix_hashes[sender - 1] = mix_hash;
        self.messages.push(message);

        for i in 1..=T {
            if i != sender && self.mixing_trustees.contains(&i) {
                let message =
                    Message::MixSignature(self.cfg_hash, self.pk_hash, input_hash, mix_hash, i);
                self.messages.push(message);
            }
        }
    }
}

impl<C: Context, const W: usize, const T: usize, const P: usize> std::fmt::Debug
    for HashBoard<C, W, T, P>
{
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        let as_strings: Vec<String> = self.messages.iter().map(|m| format!("{:?}", m)).collect();

        write!(f, "{}", as_strings.join(", "))
    }
}

//! Shared types for the private multisig ZK layer.
//!
//! These types are used in three places:
//! 1. The Risc0 membership-proof guest (inside `membership_circuit/guest`)
//! 2. The host-side prover (inside `membership_circuit`)
//! 3. The LEZ multisig program (inside `multisig_program`) when verifying receipts
//!
//! Everything here is `no_std`-friendly so the same crate can be pulled into
//! the guest build.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Merkle tree depth. 2^10 = 1024 members max per multisig.
/// Grow if needed; every +1 adds one sibling to the witness (32 bytes) and
/// one compression to prove (negligible on Risc0's SHA accelerator).
pub const MERKLE_DEPTH: usize = 10;

/// Versioned domain tag. Change on breaking circuit changes.
pub const DOMAIN_TAG: &[u8] = b"lez-private-multisig-v1";

/// A 32-byte commitment — sha256(secret || view_salt).
pub type Commitment = [u8; 32];

/// A 32-byte nullifier — scoped to (proposal, vote kind, multisig).
pub type Nullifier = [u8; 32];

/// Merkle root over member commitments. Leaves are commitments;
/// empty slots use `EMPTY_LEAF`.
pub type MerkleRoot = [u8; 32];

/// Value used for unfilled leaves. Choosing a fixed non-zero bytestring
/// prevents `commitment == 0` from accidentally matching an empty slot.
pub const EMPTY_LEAF: [u8; 32] = *b"lez-private-multisig-empty-leaf!";

/// Kind of vote being cast. Included in the nullifier so a member can
/// reject a proposal they previously approved without their rejection
/// colliding with the approval nullifier.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum VoteType {
    Propose = 1,
    Approve = 2,
    Reject = 3,
}

impl VoteType {
    pub fn as_byte(self) -> u8 {
        self as u8
    }
}

/// Public journal committed by the membership-proof guest.
///
/// Everything in here becomes on-chain data visible to the multisig program
/// and to external observers. The member's secret and Merkle path are NOT here
/// (those are the private witness).
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct ProofJournal {
    /// Merkle root of the member set at the time of proving.
    pub members_root: MerkleRoot,
    /// Which multisig this proof is scoped to.
    pub multisig_create_key: [u8; 32],
    /// The proposal being voted on (derived from create_key + proposal_index).
    pub proposal_id: [u8; 32],
    /// Whether this is a propose / approve / reject action.
    pub vote_type: VoteType,
    /// Anti-double-vote tag. Uniquely determined by (secret, scope).
    pub nullifier: Nullifier,
}

impl ProofJournal {
    /// Canonical byte encoding. Used both by the guest (to commit) and by the
    /// verifier (to decode the receipt journal).
    pub fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("ProofJournal borsh encoding")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, borsh::io::Error> {
        borsh::from_slice(bytes)
    }
}

/// Hash two Merkle children into a parent.
pub fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"NODE");
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Hash a leaf commitment. Domain-separated from internal nodes so a leaf
/// value can never be interpreted as a branch value.
pub fn hash_leaf(commitment: &Commitment) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"LEAF");
    h.update(commitment);
    h.finalize().into()
}

/// Derive a commitment from a member secret.
///
/// `view_salt` lets a member rotate their commitment without rotating the
/// underlying secret — useful for key hygiene across multiple multisigs.
pub fn commitment_from_secret(secret: &[u8; 32], view_salt: &[u8; 32]) -> Commitment {
    let mut h = Sha256::new();
    h.update(DOMAIN_TAG);
    h.update(b"COMMIT");
    h.update(secret);
    h.update(view_salt);
    h.finalize().into()
}

/// Derive the proposal_id that scopes nullifiers for a given proposal.
///
/// Binding to (create_key, proposal_index) means a nullifier minted for
/// proposal N cannot be replayed on proposal M in the same multisig, or on
/// any proposal in a different multisig.
pub fn proposal_id(create_key: &[u8; 32], proposal_index: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DOMAIN_TAG);
    h.update(b"PROPOSAL");
    h.update(create_key);
    h.update(&proposal_index.to_be_bytes());
    h.finalize().into()
}

/// Derive the nullifier a given secret must produce for a given scope.
///
/// The circuit enforces nullifier == this, so the public on-chain check
/// `nullifier not in used_set` is sufficient to prevent double voting.
pub fn nullifier_from_secret(
    secret: &[u8; 32],
    proposal_id: &[u8; 32],
    vote_type: VoteType,
    create_key: &[u8; 32],
) -> Nullifier {
    let mut h = Sha256::new();
    h.update(DOMAIN_TAG);
    h.update(b"NULLIFIER");
    h.update(secret);
    h.update(proposal_id);
    h.update(&[vote_type.as_byte()]);
    h.update(create_key);
    h.finalize().into()
}

/// Verify a Merkle path leads from a leaf commitment to a claimed root.
///
/// `path_bits` is the leaf index: bit i (LSB first) says whether the sibling
/// at level i is on the right (0) or left (1).
pub fn verify_merkle_path(
    commitment: &Commitment,
    path_bits: u32,
    siblings: &[[u8; 32]; MERKLE_DEPTH],
    expected_root: &MerkleRoot,
) -> bool {
    let mut node = hash_leaf(commitment);
    for level in 0..MERKLE_DEPTH {
        let sibling = &siblings[level];
        let bit = (path_bits >> level) & 1;
        node = if bit == 0 {
            hash_pair(&node, sibling)
        } else {
            hash_pair(sibling, &node)
        };
    }
    &node == expected_root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commitment_is_deterministic() {
        let sk = [7u8; 32];
        let salt = [3u8; 32];
        assert_eq!(commitment_from_secret(&sk, &salt), commitment_from_secret(&sk, &salt));
    }

    #[test]
    fn nullifier_differs_per_vote_type() {
        let sk = [1u8; 32];
        let ck = [2u8; 32];
        let pid = proposal_id(&ck, 1);
        let a = nullifier_from_secret(&sk, &pid, VoteType::Approve, &ck);
        let r = nullifier_from_secret(&sk, &pid, VoteType::Reject, &ck);
        assert_ne!(a, r);
    }

    #[test]
    fn nullifier_differs_per_proposal() {
        let sk = [1u8; 32];
        let ck = [2u8; 32];
        let n1 = nullifier_from_secret(&sk, &proposal_id(&ck, 1), VoteType::Approve, &ck);
        let n2 = nullifier_from_secret(&sk, &proposal_id(&ck, 2), VoteType::Approve, &ck);
        assert_ne!(n1, n2);
    }

    #[test]
    fn nullifier_differs_per_multisig() {
        let sk = [1u8; 32];
        let ck_a = [2u8; 32];
        let ck_b = [9u8; 32];
        let n_a = nullifier_from_secret(&sk, &proposal_id(&ck_a, 1), VoteType::Approve, &ck_a);
        let n_b = nullifier_from_secret(&sk, &proposal_id(&ck_b, 1), VoteType::Approve, &ck_b);
        assert_ne!(n_a, n_b);
    }
}

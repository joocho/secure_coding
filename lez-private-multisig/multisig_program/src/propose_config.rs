//! Propose a config change (add member, remove member, change threshold).
//!
//! Authenticated by a membership ZK proof with `vote_type = Propose`.
//! The new Merkle root (for add/remove) is committed *now* at propose
//! time — Execute later verifies it is consistent with the current root +
//! the declared action, but this prevents a malicious executor from
//! substituting a different root.
//!
//! Accounts:
//! - accounts[0]: multisig_state PDA (mut, bumps transaction_index)
//! - accounts[1]: proposal PDA (init, uninitialized)

use nssa_core::account::{Account, AccountWithMetadata};
use nssa_core::program::ChainedCall;
use multisig_core::{
    ConfigAction, MembershipJournal, MultisigState, Proposal,
};
use zk_common::{proposal_id as derive_proposal_id, VoteType};

use crate::verify::verify_and_decode;

pub fn handle(
    accounts: &[AccountWithMetadata],
    config_action: ConfigAction,
    proposal_index_arg: u64,
    membership_journal: &MembershipJournal,
) -> (Vec<Account>, Vec<ChainedCall>) {
    assert!(
        accounts.len() >= 2,
        "ProposeConfig requires multisig_state + proposal accounts"
    );
    let multisig_account = &accounts[0];
    let proposal_account = &accounts[1];

    assert!(
        proposal_account.account == Account::default(),
        "Proposal account must be uninitialized"
    );

    let state_data: Vec<u8> = multisig_account.account.data.clone().into();
    let mut state: MultisigState =
        borsh::from_slice(&state_data).expect("Failed to deserialize multisig state");

    match &config_action {
        ConfigAction::AddMember { .. } => {
            assert!(state.member_count < u8::MAX, "member_count would overflow");
        }
        ConfigAction::RemoveMember { .. } => {
            assert!(
                state.member_count > state.threshold,
                "Removing would make count fall below threshold"
            );
        }
        ConfigAction::ChangeThreshold { new_threshold } => {
            assert!(*new_threshold >= 1, "Threshold must be at least 1");
            assert!(
                *new_threshold <= state.member_count,
                "Threshold cannot exceed member count"
            );
        }
    }

    let next_index = state.next_proposal_index();
    assert_eq!(
        next_index, proposal_index_arg,
        "proposal_index arg does not match next transaction_index"
    );

    let journal = verify_and_decode(membership_journal);

    assert_eq!(journal.multisig_create_key, state.create_key);
    assert_eq!(
        journal.members_root, state.members_root,
        "Proof was generated against a different member set"
    );
    let expected_pid = derive_proposal_id(&state.create_key, next_index);
    assert_eq!(journal.proposal_id, expected_pid);
    assert_eq!(
        journal.vote_type,
        VoteType::Propose,
        "Config proposal requires Propose vote_type"
    );

    let proposal = Proposal::new_config(
        next_index,
        state.create_key,
        state.members_root,
        config_action,
        journal.nullifier,
    );

    let state_bytes = borsh::to_vec(&state).unwrap();
    let mut multisig_post = multisig_account.account.clone();
    multisig_post.data = state_bytes.try_into().unwrap();

    let proposal_bytes = borsh::to_vec(&proposal).unwrap();
    let mut proposal_post = Account::default();
    proposal_post.data = proposal_bytes.try_into().unwrap();

    (vec![multisig_post, proposal_post], vec![])
}

#[cfg(test)]
mod tests {
    use super::*;
    use nssa_core::account::AccountId;
    use zk_common::ProofJournal;

    fn make_account(id: &[u8; 32], data: Vec<u8>) -> AccountWithMetadata {
        let mut account = Account::default();
        account.data = data.try_into().unwrap();
        AccountWithMetadata {
            account_id: AccountId::new(*id),
            account,
            is_authorized: false,
        }
    }

    fn state_bytes(ck: [u8; 32], root: [u8; 32], threshold: u8, count: u8) -> Vec<u8> {
        borsh::to_vec(&MultisigState::new(ck, threshold, count, root)).unwrap()
    }

    fn journal(ck: [u8; 32], root: [u8; 32], idx: u64, null: [u8; 32]) -> Vec<u8> {
        let j = ProofJournal {
            members_root: root,
            multisig_create_key: ck,
            proposal_id: derive_proposal_id(&ck, idx),
            vote_type: VoteType::Propose,
            nullifier: null,
        };
        borsh::to_vec(&j).unwrap()
    }

    #[test]
    fn propose_add_member() {
        let ck = [1u8; 32];
        let root = [2u8; 32];
        let accounts = vec![
            make_account(&[10u8; 32], state_bytes(ck, root, 2, 3)),
            make_account(&[20u8; 32], vec![]),
        ];
        let j = journal(ck, root, 1, [9u8; 32]);
        let action = ConfigAction::AddMember {
            new_commitment: [5u8; 32],
            expected_new_root: [77u8; 32],
        };
        let (out, _) = handle(&accounts, action.clone(), 1, &j);
        let p: Proposal = borsh::from_slice(&Vec::from(out[1].data.clone())).unwrap();
        assert_eq!(p.config_action, Some(action));
    }

    #[test]
    #[should_panic(expected = "below threshold")]
    fn remove_below_threshold_rejected_at_propose_time() {
        let ck = [1u8; 32];
        let root = [2u8; 32];
        let accounts = vec![
            make_account(&[10u8; 32], state_bytes(ck, root, 2, 2)),
            make_account(&[20u8; 32], vec![]),
        ];
        let j = journal(ck, root, 1, [9u8; 32]);
        let action = ConfigAction::RemoveMember {
            target_commitment: [5u8; 32],
            expected_new_root: [77u8; 32],
        };
        handle(&accounts, action, 1, &j);
    }
}

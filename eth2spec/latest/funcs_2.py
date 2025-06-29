# pyright: reportInvalidTypeForm=false

from eth2spec.latest.constants_0 import *
from eth2spec.latest.funcs_0 import *
from eth2spec.latest.classes_0 import *
from eth2spec.latest.constants_1 import *
from eth2spec.latest.classes_1 import *
from eth2spec.latest.funcs_1 import *
from eth2spec.latest.funcs_2_read_state import *


GeneralizedIndex = int


EXECUTION_ENGINE = NoopExecutionEngine()


def get_current_slot(store: Store) -> Slot:
    return Slot(GENESIS_SLOT + get_slots_since_genesis(store))


def get_slots_since_genesis(store: Store) -> int:
    return (store.time - store.genesis_time) // config.SECONDS_PER_SLOT


def update_checkpoints(
    store: Store, justified_checkpoint: Checkpoint, finalized_checkpoint: Checkpoint
) -> None:
    """
    Update checkpoints in store if necessary
    """
    # Update justified checkpoint
    if justified_checkpoint.epoch > store.justified_checkpoint.epoch:
        store.justified_checkpoint = justified_checkpoint

    # Update finalized checkpoint
    if finalized_checkpoint.epoch > store.finalized_checkpoint.epoch:
        store.finalized_checkpoint = finalized_checkpoint


def get_checkpoint_block(store: Store, root: Root, epoch: Epoch) -> Root:
    """
    Compute the checkpoint block for epoch ``epoch`` in the chain of block ``root``
    """
    epoch_first_slot = compute_start_slot_at_epoch(epoch)
    return get_ancestor(store, root, epoch_first_slot)


def get_ancestor(store: Store, root: Root, slot: Slot) -> Root:
    block = store.blocks[root]
    if block.slot > slot:
        return get_ancestor(store, block.parent_root, slot)
    return root


def weigh_justification_and_finalization(
    state: BeaconState,
    total_active_balance: Gwei,
    previous_epoch_target_balance: Gwei,
    current_epoch_target_balance: Gwei,
) -> None:
    previous_epoch = get_previous_epoch(state)
    current_epoch = get_current_epoch(state)
    old_previous_justified_checkpoint = state.previous_justified_checkpoint
    old_current_justified_checkpoint = state.current_justified_checkpoint

    # Process justifications
    state.previous_justified_checkpoint = state.current_justified_checkpoint
    state.justification_bits[1:] = state.justification_bits[
        : JUSTIFICATION_BITS_LENGTH - 1
    ]
    state.justification_bits[0] = 0b0
    if previous_epoch_target_balance * 3 >= total_active_balance * 2:
        state.current_justified_checkpoint = Checkpoint(
            epoch=previous_epoch, root=get_block_root(state, previous_epoch)
        )
        state.justification_bits[1] = 0b1
    if current_epoch_target_balance * 3 >= total_active_balance * 2:
        state.current_justified_checkpoint = Checkpoint(
            epoch=current_epoch, root=get_block_root(state, current_epoch)
        )
        state.justification_bits[0] = 0b1

    # Process finalizations
    bits = state.justification_bits
    # The 2nd/3rd/4th most recent epochs are justified, the 2nd using the 4th as source
    if all(bits[1:4]) and old_previous_justified_checkpoint.epoch + 3 == current_epoch:
        state.finalized_checkpoint = old_previous_justified_checkpoint
    # The 2nd/3rd most recent epochs are justified, the 2nd using the 3rd as source
    if all(bits[1:3]) and old_previous_justified_checkpoint.epoch + 2 == current_epoch:
        state.finalized_checkpoint = old_previous_justified_checkpoint
    # The 1st/2nd/3rd most recent epochs are justified, the 1st using the 3rd as source
    if all(bits[0:3]) and old_current_justified_checkpoint.epoch + 2 == current_epoch:
        state.finalized_checkpoint = old_current_justified_checkpoint
    # The 1st/2nd most recent epochs are justified, the 1st using the 2nd as source
    if all(bits[0:2]) and old_current_justified_checkpoint.epoch + 1 == current_epoch:
        state.finalized_checkpoint = old_current_justified_checkpoint


def get_current_store_epoch(store: Store) -> Epoch:
    return compute_epoch_at_slot(get_current_slot(store))


def increase_balance(state: BeaconState, index: ValidatorIndex, delta: Gwei) -> None:
    """
    Increase the validator balance at index ``index`` by ``delta``.
    """
    state.balances[index] += delta


def decrease_balance(state: BeaconState, index: ValidatorIndex, delta: Gwei) -> None:
    """
    Decrease the validator balance at index ``index`` by ``delta``, with underflow protection.
    """
    state.balances[index] = (
        0 if delta > state.balances[index] else state.balances[index] - delta
    )


def compute_consolidation_epoch_and_update_churn(
    state: BeaconState, consolidation_balance: Gwei
) -> Epoch:
    earliest_consolidation_epoch = max(
        state.earliest_consolidation_epoch,
        compute_activation_exit_epoch(get_current_epoch(state)),
    )
    per_epoch_consolidation_churn = get_consolidation_churn_limit(state)
    # New epoch for consolidations.
    if state.earliest_consolidation_epoch < earliest_consolidation_epoch:
        consolidation_balance_to_consume = per_epoch_consolidation_churn
    else:
        consolidation_balance_to_consume = state.consolidation_balance_to_consume

    # Consolidation doesn't fit in the current earliest epoch.
    if consolidation_balance > consolidation_balance_to_consume:
        balance_to_process = consolidation_balance - consolidation_balance_to_consume
        additional_epochs = (
            balance_to_process - 1
        ) // per_epoch_consolidation_churn + 1
        earliest_consolidation_epoch += additional_epochs
        consolidation_balance_to_consume += (
            additional_epochs * per_epoch_consolidation_churn
        )

    # Consume the balance and update state variables.
    state.consolidation_balance_to_consume = (
        consolidation_balance_to_consume - consolidation_balance
    )
    state.earliest_consolidation_epoch = earliest_consolidation_epoch

    return state.earliest_consolidation_epoch


def queue_excess_active_balance(state: BeaconState, index: ValidatorIndex) -> None:
    balance = state.balances[index]
    if balance > MIN_ACTIVATION_BALANCE:
        excess_balance = balance - MIN_ACTIVATION_BALANCE
        state.balances[index] = MIN_ACTIVATION_BALANCE
        validator = state.validators[index]
        # Use bls.G2_POINT_AT_INFINITY as a signature field placeholder
        # and GENESIS_SLOT to distinguish from a pending deposit request
        state.pending_deposits.append(
            PendingDeposit(
                pubkey=validator.pubkey,
                withdrawal_credentials=validator.withdrawal_credentials,
                amount=excess_balance,
                signature=bls.G2_POINT_AT_INFINITY,
                slot=GENESIS_SLOT,
            )
        )


def add_validator_to_registry(
    state: BeaconState,
    pubkey: BLSPubkey,
    withdrawal_credentials: Bytes32,
    amount: uint64,
) -> None:
    index = get_index_for_new_validator(state)
    # [Modified in Electra:EIP7251]
    validator = get_validator_from_deposit(pubkey, withdrawal_credentials, amount)
    set_or_append_list(state.validators, index, validator)
    set_or_append_list(state.balances, index, amount)
    set_or_append_list(
        state.previous_epoch_participation, index, ParticipationFlags(0b0000_0000)
    )
    set_or_append_list(
        state.current_epoch_participation, index, ParticipationFlags(0b0000_0000)
    )
    set_or_append_list(state.inactivity_scores, index, uint64(0))


def is_valid_normalized_merkle_branch(
    leaf: Bytes32, branch: Sequence[Bytes32], gindex: GeneralizedIndex, root: Root
) -> bool:
    depth = floorlog2(gindex)
    index = get_subtree_index(gindex)
    num_extra = len(branch) - depth
    for i in range(num_extra):
        if branch[i] != Bytes32():
            return False
    return is_valid_merkle_branch(leaf, branch[num_extra:], depth, index, root)


def current_sync_committee_gindex_at_slot(slot: Slot) -> GeneralizedIndex:
    epoch = compute_epoch_at_slot(slot)

    # [Modified in Electra]
    if epoch >= config.ELECTRA_FORK_EPOCH:
        return CURRENT_SYNC_COMMITTEE_GINDEX_ELECTRA
    return CURRENT_SYNC_COMMITTEE_GINDEX


def get_weight(store: Store, root: Root) -> Gwei:
    state = store.checkpoint_states[store.justified_checkpoint]
    unslashed_and_active_indices = [
        i
        for i in get_active_validator_indices(state, get_current_epoch(state))
        if not state.validators[i].slashed
    ]
    attestation_score = Gwei(
        sum(
            state.validators[i].effective_balance
            for i in unslashed_and_active_indices
            if (
                i in store.latest_messages
                and i not in store.equivocating_indices
                and get_ancestor(
                    store, store.latest_messages[i].root, store.blocks[root].slot
                )
                == root
            )
        )
    )
    if store.proposer_boost_root == Root():
        # Return only attestation score if ``proposer_boost_root`` is not set
        return attestation_score

    # Calculate proposer score if ``proposer_boost_root`` is set
    proposer_score = Gwei(0)
    # Boost is applied if ``root`` is an ancestor of ``proposer_boost_root``
    if get_ancestor(store, store.proposer_boost_root, store.blocks[root].slot) == root:
        proposer_score = get_proposer_score(store)
    return attestation_score + proposer_score


def get_proposer_score(store: Store) -> Gwei:
    justified_checkpoint_state = store.checkpoint_states[store.justified_checkpoint]
    committee_weight = (
        get_total_active_balance(justified_checkpoint_state) // SLOTS_PER_EPOCH
    )
    return (committee_weight * config.PROPOSER_SCORE_BOOST) // 100


def compute_sync_committee_period(epoch: Epoch) -> uint64:
    return epoch // EPOCHS_PER_SYNC_COMMITTEE_PERIOD


def initiate_validator_exit(state: BeaconState, index: ValidatorIndex) -> None:
    """
    Initiate the exit of the validator with index ``index``.
    """
    # Return if validator already initiated exit
    validator = state.validators[index]
    if validator.exit_epoch != FAR_FUTURE_EPOCH:
        return

    # Compute exit queue epoch [Modified in Electra:EIP7251]
    exit_queue_epoch = compute_exit_epoch_and_update_churn(
        state, validator.effective_balance
    )

    # Set validator exit epoch and withdrawable epoch
    validator.exit_epoch = exit_queue_epoch
    validator.withdrawable_epoch = Epoch(
        validator.exit_epoch + config.MIN_VALIDATOR_WITHDRAWABILITY_DELAY
    )


def compute_exit_epoch_and_update_churn(
    state: BeaconState, exit_balance: Gwei
) -> Epoch:
    earliest_exit_epoch = max(
        state.earliest_exit_epoch,
        compute_activation_exit_epoch(get_current_epoch(state)),
    )
    per_epoch_churn = get_activation_exit_churn_limit(state)
    # New epoch for exits.
    if state.earliest_exit_epoch < earliest_exit_epoch:
        exit_balance_to_consume = per_epoch_churn
    else:
        exit_balance_to_consume = state.exit_balance_to_consume

    # Exit doesn't fit in the current earliest epoch.
    if exit_balance > exit_balance_to_consume:
        balance_to_process = exit_balance - exit_balance_to_consume
        additional_epochs = (balance_to_process - 1) // per_epoch_churn + 1
        earliest_exit_epoch += additional_epochs
        exit_balance_to_consume += additional_epochs * per_epoch_churn

    # Consume the balance and update state variables.
    state.exit_balance_to_consume = exit_balance_to_consume - exit_balance
    state.earliest_exit_epoch = earliest_exit_epoch

    return state.earliest_exit_epoch

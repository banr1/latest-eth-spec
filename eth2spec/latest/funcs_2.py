# pyright: reportInvalidTypeForm=false

from typing import Tuple

from eth2spec.latest.constants_0 import *
from eth2spec.latest.funcs_0 import *
from eth2spec.latest.classes_0 import *
from eth2spec.latest.constants_1 import *
from eth2spec.latest.classes_1 import *
from eth2spec.latest.funcs_1 import *


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


def get_current_epoch(state: BeaconState) -> Epoch:
    """
    Return the current epoch.
    """
    return compute_epoch_at_slot(state.slot)


def get_unslashed_participating_indices(
    state: BeaconState, flag_index: int, epoch: Epoch
) -> Set[ValidatorIndex]:
    """
    Return the set of validator indices that are both active and unslashed for the given ``flag_index`` and ``epoch``.
    """
    assert epoch in (get_previous_epoch(state), get_current_epoch(state))
    if epoch == get_current_epoch(state):
        epoch_participation = state.current_epoch_participation
    else:
        epoch_participation = state.previous_epoch_participation
    active_validator_indices = get_active_validator_indices(state, epoch)
    participating_indices = [
        i
        for i in active_validator_indices
        if has_flag(epoch_participation[i], flag_index)
    ]
    return set(
        filter(lambda index: not state.validators[index].slashed, participating_indices)
    )


def get_total_active_balance(state: BeaconState) -> Gwei:
    """
    Return the combined effective balance of the active validators.
    Note: ``get_total_balance`` returns ``EFFECTIVE_BALANCE_INCREMENT`` Gwei minimum to avoid divisions by zero.
    """
    return get_total_balance(
        state, set(get_active_validator_indices(state, get_current_epoch(state)))
    )


def get_previous_epoch(state: BeaconState) -> Epoch:
    """`
    Return the previous epoch (unless the current epoch is ``GENESIS_EPOCH``).
    """
    current_epoch = get_current_epoch(state)
    return GENESIS_EPOCH if current_epoch == GENESIS_EPOCH else Epoch(current_epoch - 1)


def get_total_balance(state: BeaconState, indices: Set[ValidatorIndex]) -> Gwei:
    """
    Return the combined effective balance of the ``indices``.
    ``EFFECTIVE_BALANCE_INCREMENT`` Gwei minimum to avoid divisions by zero.
    Math safe up to ~10B ETH, after which this overflows uint64.
    """
    return Gwei(
        max(
            EFFECTIVE_BALANCE_INCREMENT,
            sum([state.validators[index].effective_balance for index in indices]),
        )
    )


def get_active_validator_indices(
    state: BeaconState, epoch: Epoch
) -> Sequence[ValidatorIndex]:
    """
    Return the sequence of active validator indices at ``epoch``.
    """
    return [
        ValidatorIndex(i)
        for i, v in enumerate(state.validators)
        if is_active_validator(v, epoch)
    ]


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


def get_block_root(state: BeaconState, epoch: Epoch) -> Root:
    """
    Return the block root at the start of a recent ``epoch``.
    """
    return get_block_root_at_slot(state, compute_start_slot_at_epoch(epoch))


def get_block_root_at_slot(state: BeaconState, slot: Slot) -> Root:
    """
    Return the block root at a recent ``slot``.
    """
    assert slot < state.slot <= slot + SLOTS_PER_HISTORICAL_ROOT
    return state.block_roots[slot % SLOTS_PER_HISTORICAL_ROOT]


def get_domain(
    state: BeaconState, domain_type: DomainType, epoch: Epoch = None
) -> Domain:
    """
    Return the signature domain (fork version concatenated with domain type) of a message.
    """
    epoch = get_current_epoch(state) if epoch is None else epoch
    fork_version = (
        state.fork.previous_version
        if epoch < state.fork.epoch
        else state.fork.current_version
    )
    return compute_domain(domain_type, fork_version, state.genesis_validators_root)


def get_current_store_epoch(store: Store) -> Epoch:
    return compute_epoch_at_slot(get_current_slot(store))


def get_eligible_validator_indices(state: BeaconState) -> Sequence[ValidatorIndex]:
    previous_epoch = get_previous_epoch(state)
    return [
        ValidatorIndex(index)
        for index, v in enumerate(state.validators)
        if is_active_validator(v, previous_epoch)
        or (v.slashed and previous_epoch + 1 < v.withdrawable_epoch)
    ]


def is_in_inactivity_leak(state: BeaconState) -> bool:
    return get_finality_delay(state) > MIN_EPOCHS_TO_INACTIVITY_PENALTY


def get_beacon_proposer_index(state: BeaconState) -> ValidatorIndex:
    """
    Return the beacon proposer index at the current slot.
    """
    epoch = get_current_epoch(state)
    seed = hash(
        get_seed(state, epoch, DOMAIN_BEACON_PROPOSER) + uint_to_bytes(state.slot)
    )
    indices = get_active_validator_indices(state, epoch)
    return compute_proposer_index(state, indices, seed)


def get_finality_delay(state: BeaconState) -> uint64:
    return get_previous_epoch(state) - state.finalized_checkpoint.epoch


def get_seed(state: BeaconState, epoch: Epoch, domain_type: DomainType) -> Bytes32:
    """
    Return the seed at ``epoch``.
    """
    mix = get_randao_mix(
        state, Epoch(epoch + EPOCHS_PER_HISTORICAL_VECTOR - MIN_SEED_LOOKAHEAD - 1)
    )  # Avoid underflow
    return hash(domain_type + uint_to_bytes(epoch) + mix)


def compute_proposer_index(
    state: BeaconState, indices: Sequence[ValidatorIndex], seed: Bytes32
) -> ValidatorIndex:
    """
    Return from ``indices`` a random index sampled by effective balance.
    """
    assert len(indices) > 0
    MAX_RANDOM_VALUE = 2**16 - 1  # [Modified in Electra]
    i = uint64(0)
    total = uint64(len(indices))
    while True:
        candidate_index = indices[compute_shuffled_index(i % total, total, seed)]
        # [Modified in Electra]
        random_bytes = hash(seed + uint_to_bytes(i // 16))
        offset = i % 16 * 2
        random_value = bytes_to_uint64(random_bytes[offset : offset + 2])
        effective_balance = state.validators[candidate_index].effective_balance
        # [Modified in Electra:EIP7251]
        if (
            effective_balance * MAX_RANDOM_VALUE
            >= MAX_EFFECTIVE_BALANCE_ELECTRA * random_value
        ):
            return candidate_index
        i += 1


def get_randao_mix(state: BeaconState, epoch: Epoch) -> Bytes32:
    """
    Return the randao mix at a recent ``epoch``.
    """
    return state.randao_mixes[epoch % EPOCHS_PER_HISTORICAL_VECTOR]


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


def get_base_reward_per_increment(state: BeaconState) -> Gwei:
    return Gwei(
        EFFECTIVE_BALANCE_INCREMENT
        * BASE_REWARD_FACTOR
        // integer_squareroot(get_total_active_balance(state))
    )


def get_attesting_indices(
    state: BeaconState, attestation: Attestation
) -> Set[ValidatorIndex]:
    """
    Return the set of attesting indices corresponding to ``aggregation_bits`` and ``committee_bits``.
    """
    output: Set[ValidatorIndex] = set()
    committee_indices = get_committee_indices(attestation.committee_bits)
    committee_offset = 0
    for committee_index in committee_indices:
        committee = get_beacon_committee(state, attestation.data.slot, committee_index)
        committee_attesters = set(
            attester_index
            for i, attester_index in enumerate(committee)
            if attestation.aggregation_bits[committee_offset + i]
        )
        output = output.union(committee_attesters)

        committee_offset += len(committee)

    return output


def get_beacon_committee(
    state: BeaconState, slot: Slot, index: CommitteeIndex
) -> Sequence[ValidatorIndex]:
    """
    Return the beacon committee at ``slot`` for ``index``.
    """
    epoch = compute_epoch_at_slot(slot)
    committees_per_slot = get_committee_count_per_slot(state, epoch)
    return compute_committee(
        indices=get_active_validator_indices(state, epoch),
        seed=get_seed(state, epoch, DOMAIN_BEACON_ATTESTER),
        index=(slot % SLOTS_PER_EPOCH) * committees_per_slot + index,
        count=committees_per_slot * SLOTS_PER_EPOCH,
    )


def get_committee_count_per_slot(state: BeaconState, epoch: Epoch) -> uint64:
    """
    Return the number of committees in each slot for the given ``epoch``.
    """
    return max(
        uint64(1),
        min(
            MAX_COMMITTEES_PER_SLOT,
            uint64(len(get_active_validator_indices(state, epoch)))
            // SLOTS_PER_EPOCH
            // TARGET_COMMITTEE_SIZE,
        ),
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


def get_consolidation_churn_limit(state: BeaconState) -> Gwei:
    return get_balance_churn_limit(state) - get_activation_exit_churn_limit(state)


def get_pending_balance_to_withdraw(
    state: BeaconState, validator_index: ValidatorIndex
) -> Gwei:
    return sum(
        withdrawal.amount
        for withdrawal in state.pending_partial_withdrawals
        if withdrawal.validator_index == validator_index
    )


def get_balance_churn_limit(state: BeaconState) -> Gwei:
    """
    Return the churn limit for the current epoch.
    """
    churn = max(
        config.MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA,
        get_total_active_balance(state) // config.CHURN_LIMIT_QUOTIENT,
    )
    return churn - churn % EFFECTIVE_BALANCE_INCREMENT


def get_activation_exit_churn_limit(state: BeaconState) -> Gwei:
    """
    Return the churn limit for the current epoch dedicated to activations and exits.
    """
    return min(
        config.MAX_PER_EPOCH_ACTIVATION_EXIT_CHURN_LIMIT, get_balance_churn_limit(state)
    )


def get_base_reward(state: BeaconState, index: ValidatorIndex) -> Gwei:
    """
    Return the base reward for the validator defined by ``index`` with respect to the current ``state``.
    """
    increments = (
        state.validators[index].effective_balance // EFFECTIVE_BALANCE_INCREMENT
    )
    return Gwei(increments * get_base_reward_per_increment(state))


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


def get_next_sync_committee(state: BeaconState) -> SyncCommittee:
    """
    Return the next sync committee, with possible pubkey duplicates.
    """
    indices = get_next_sync_committee_indices(state)
    pubkeys = [state.validators[index].pubkey for index in indices]
    aggregate_pubkey = eth_aggregate_pubkeys(pubkeys)
    return SyncCommittee(pubkeys=pubkeys, aggregate_pubkey=aggregate_pubkey)


def get_next_sync_committee_indices(state: BeaconState) -> Sequence[ValidatorIndex]:
    """
    Return the sync committee indices, with possible duplicates, for the next sync committee.
    """
    epoch = Epoch(get_current_epoch(state) + 1)

    MAX_RANDOM_VALUE = 2**16 - 1  # [Modified in Electra]
    active_validator_indices = get_active_validator_indices(state, epoch)
    active_validator_count = uint64(len(active_validator_indices))
    seed = get_seed(state, epoch, DOMAIN_SYNC_COMMITTEE)
    i = uint64(0)
    sync_committee_indices: List[ValidatorIndex] = []
    while len(sync_committee_indices) < SYNC_COMMITTEE_SIZE:
        shuffled_index = compute_shuffled_index(
            uint64(i % active_validator_count), active_validator_count, seed
        )
        candidate_index = active_validator_indices[shuffled_index]
        # [Modified in Electra]
        random_bytes = hash(seed + uint_to_bytes(i // 16))
        offset = i % 16 * 2
        random_value = bytes_to_uint64(random_bytes[offset : offset + 2])
        effective_balance = state.validators[candidate_index].effective_balance
        # [Modified in Electra:EIP7251]
        if (
            effective_balance * MAX_RANDOM_VALUE
            >= MAX_EFFECTIVE_BALANCE_ELECTRA * random_value
        ):
            sync_committee_indices.append(candidate_index)
        i += 1
    return sync_committee_indices


def get_expected_withdrawals(state: BeaconState) -> Tuple[Sequence[Withdrawal], uint64]:
    epoch = get_current_epoch(state)
    withdrawal_index = state.next_withdrawal_index
    validator_index = state.next_withdrawal_validator_index
    withdrawals: List[Withdrawal] = []
    processed_partial_withdrawals_count = 0

    # [New in Electra:EIP7251] Consume pending partial withdrawals
    for withdrawal in state.pending_partial_withdrawals:
        if (
            withdrawal.withdrawable_epoch > epoch
            or len(withdrawals) == MAX_PENDING_PARTIALS_PER_WITHDRAWALS_SWEEP
        ):
            break

        validator = state.validators[withdrawal.validator_index]
        has_sufficient_effective_balance = (
            validator.effective_balance >= MIN_ACTIVATION_BALANCE
        )
        total_withdrawn = sum(
            w.amount
            for w in withdrawals
            if w.validator_index == withdrawal.validator_index
        )
        balance = state.balances[withdrawal.validator_index] - total_withdrawn
        has_excess_balance = balance > MIN_ACTIVATION_BALANCE
        if (
            validator.exit_epoch == FAR_FUTURE_EPOCH
            and has_sufficient_effective_balance
            and has_excess_balance
        ):
            withdrawable_balance = min(
                balance - MIN_ACTIVATION_BALANCE, withdrawal.amount
            )
            withdrawals.append(
                Withdrawal(
                    index=withdrawal_index,
                    validator_index=withdrawal.validator_index,
                    address=ExecutionAddress(validator.withdrawal_credentials[12:]),
                    amount=withdrawable_balance,
                )
            )
            withdrawal_index += WithdrawalIndex(1)

        processed_partial_withdrawals_count += 1

    # Sweep for remaining.
    bound = min(len(state.validators), MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP)
    for _ in range(bound):
        validator = state.validators[validator_index]
        # [Modified in Electra:EIP7251]
        total_withdrawn = sum(
            w.amount for w in withdrawals if w.validator_index == validator_index
        )
        balance = state.balances[validator_index] - total_withdrawn
        if is_fully_withdrawable_validator(validator, balance, epoch):
            withdrawals.append(
                Withdrawal(
                    index=withdrawal_index,
                    validator_index=validator_index,
                    address=ExecutionAddress(validator.withdrawal_credentials[12:]),
                    amount=balance,
                )
            )
            withdrawal_index += WithdrawalIndex(1)
        elif is_partially_withdrawable_validator(validator, balance):
            withdrawals.append(
                Withdrawal(
                    index=withdrawal_index,
                    validator_index=validator_index,
                    address=ExecutionAddress(validator.withdrawal_credentials[12:]),
                    # [Modified in Electra:EIP7251]
                    amount=balance - get_max_effective_balance(validator),
                )
            )
            withdrawal_index += WithdrawalIndex(1)
        if len(withdrawals) == MAX_WITHDRAWALS_PER_PAYLOAD:
            break
        validator_index = ValidatorIndex((validator_index + 1) % len(state.validators))
    return withdrawals, processed_partial_withdrawals_count


def get_inactivity_penalty_deltas(
    state: BeaconState,
) -> Tuple[Sequence[Gwei], Sequence[Gwei]]:
    """
    Return the inactivity penalty deltas by considering timely target participation flags and inactivity scores.
    """
    rewards = [Gwei(0) for _ in range(len(state.validators))]
    penalties = [Gwei(0) for _ in range(len(state.validators))]
    previous_epoch = get_previous_epoch(state)
    matching_target_indices = get_unslashed_participating_indices(
        state, TIMELY_TARGET_FLAG_INDEX, previous_epoch
    )
    for index in get_eligible_validator_indices(state):
        if index not in matching_target_indices:
            penalty_numerator = (
                state.validators[index].effective_balance
                * state.inactivity_scores[index]
            )
            # [Modified in Bellatrix]
            penalty_denominator = (
                config.INACTIVITY_SCORE_BIAS * INACTIVITY_PENALTY_QUOTIENT_BELLATRIX
            )
            penalties[index] += Gwei(penalty_numerator // penalty_denominator)
    return rewards, penalties


def compute_timestamp_at_slot(state: BeaconState, slot: Slot) -> uint64:
    slots_since_genesis = slot - GENESIS_SLOT
    return uint64(state.genesis_time + slots_since_genesis * config.SECONDS_PER_SLOT)


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


def get_index_for_new_validator(state: BeaconState) -> ValidatorIndex:
    return ValidatorIndex(len(state.validators))


def is_valid_light_client_header(header: LightClientHeader) -> bool:
    epoch = compute_epoch_at_slot(header.beacon.slot)

    # [New in Deneb:EIP4844]
    if epoch < config.DENEB_FORK_EPOCH:
        if header.execution.blob_gas_used != uint64(0):
            return False
        if header.execution.excess_blob_gas != uint64(0):
            return False

    if epoch < config.CAPELLA_FORK_EPOCH:
        return (
            header.execution == ExecutionPayloadHeader()
            and header.execution_branch == ExecutionBranch()
        )

    return is_valid_merkle_branch(
        leaf=get_lc_execution_root(header),
        branch=header.execution_branch,
        depth=floorlog2(EXECUTION_PAYLOAD_GINDEX),
        index=get_subtree_index(EXECUTION_PAYLOAD_GINDEX),
        root=header.beacon.body_root,
    )


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


def get_unslashed_attesting_indices(
    state: BeaconState, attestations: Sequence[PendingAttestation]
) -> Set[ValidatorIndex]:
    output: Set[ValidatorIndex] = set()
    for a in attestations:
        output = output.union(get_attesting_indices(state, a))
    return set(filter(lambda index: not state.validators[index].slashed, output))


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

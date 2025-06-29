# pyright: reportInvalidTypeForm=false

from typing import Tuple

from eth2spec.latest.constants_0 import *
from eth2spec.latest.funcs_0 import *
from eth2spec.latest.classes_0 import *
from eth2spec.latest.constants_1 import *
from eth2spec.latest.classes_1 import *
from eth2spec.latest.funcs_1 import *


def get_current_epoch(state: BeaconState) -> Epoch:
    """
    Return the current epoch.
    """
    return compute_epoch_at_slot(state.slot)


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


def get_eligible_validator_indices(state: BeaconState) -> Sequence[ValidatorIndex]:
    previous_epoch = get_previous_epoch(state)
    return [
        ValidatorIndex(index)
        for index, v in enumerate(state.validators)
        if is_active_validator(v, previous_epoch)
        or (v.slashed and previous_epoch + 1 < v.withdrawable_epoch)
    ]


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


def get_randao_mix(state: BeaconState, epoch: Epoch) -> Bytes32:
    """
    Return the randao mix at a recent ``epoch``.
    """
    return state.randao_mixes[epoch % EPOCHS_PER_HISTORICAL_VECTOR]


def get_base_reward_per_increment(state: BeaconState) -> Gwei:
    return Gwei(
        EFFECTIVE_BALANCE_INCREMENT
        * BASE_REWARD_FACTOR
        // integer_squareroot(get_total_active_balance(state))
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


def get_consolidation_churn_limit(state: BeaconState) -> Gwei:
    return get_balance_churn_limit(state) - get_activation_exit_churn_limit(state)


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


def get_index_for_new_validator(state: BeaconState) -> ValidatorIndex:
    return ValidatorIndex(len(state.validators))


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


def is_in_inactivity_leak(state: BeaconState) -> bool:
    return get_finality_delay(state) > MIN_EPOCHS_TO_INACTIVITY_PENALTY


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


def get_pending_balance_to_withdraw(
    state: BeaconState, validator_index: ValidatorIndex
) -> Gwei:
    return sum(
        withdrawal.amount
        for withdrawal in state.pending_partial_withdrawals
        if withdrawal.validator_index == validator_index
    )


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


def get_unslashed_attesting_indices(
    state: BeaconState, attestations: Sequence[PendingAttestation]
) -> Set[ValidatorIndex]:
    output: Set[ValidatorIndex] = set()
    for a in attestations:
        output = output.union(get_attesting_indices(state, a))
    return set(filter(lambda index: not state.validators[index].slashed, output))


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


def compute_timestamp_at_slot(state: BeaconState, slot: Slot) -> uint64:
    slots_since_genesis = slot - GENESIS_SLOT
    return uint64(state.genesis_time + slots_since_genesis * config.SECONDS_PER_SLOT)

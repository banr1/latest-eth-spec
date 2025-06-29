# pyright: reportInvalidTypeForm=false

from typing import Any, Callable, Sequence

from eth2spec.utils.ssz.ssz_impl import hash_tree_root
from eth2spec.utils.ssz.ssz_typing import List, uint64, Bytes32
from eth2spec.utils import bls
from eth2spec.utils.hash_function import hash

from eth2spec.phase0 import mainnet as phase0

from eth2spec.latest_2.constants import *
from eth2spec.latest_2.classes import *
from eth2spec.latest_2.hyper_read_funcs import *


EXECUTION_ENGINE = NoopExecutionEngine()


############## 間接的 ##############


def compute_new_state_root(state: BeaconState, block: BeaconBlock) -> Root:
    temp_state: BeaconState = state.copy()
    signed_block = SignedBeaconBlock(message=block)
    state_transition(temp_state, signed_block, validate_result=False)
    return hash_tree_root(temp_state)


def state_transition(
    state: BeaconState, signed_block: SignedBeaconBlock, validate_result: bool = True
) -> None:
    block = signed_block.message
    # Process slots (including those with no blocks) since block
    process_slots(state, block.slot)
    # Verify signature
    if validate_result:
        assert verify_block_signature(state, signed_block)
    # Process block
    process_block(state, block)
    # Verify state root
    if validate_result:
        assert block.state_root == hash_tree_root(state)


def process_block(state: BeaconState, block: BeaconBlock) -> None:
    process_block_header(state, block)
    # [Modified in Electra:EIP7251]
    process_withdrawals(state, block.body.execution_payload)
    # [Modified in Electra:EIP6110]
    process_execution_payload(state, block.body, EXECUTION_ENGINE)
    process_randao(state, block.body)
    process_eth1_data(state, block.body)
    # [Modified in Electra:EIP6110:EIP7002:EIP7549:EIP7251]
    process_operations(state, block.body)
    process_sync_aggregate(state, block.body.sync_aggregate)


def process_operations(state: BeaconState, body: BeaconBlockBody) -> None:
    # [Modified in Electra:EIP6110]
    # Disable former deposit mechanism once all prior deposits are processed
    eth1_deposit_index_limit = min(
        state.eth1_data.deposit_count, state.deposit_requests_start_index
    )
    if state.eth1_deposit_index < eth1_deposit_index_limit:
        assert len(body.deposits) == min(
            MAX_DEPOSITS, eth1_deposit_index_limit - state.eth1_deposit_index
        )
    else:
        assert len(body.deposits) == 0

    def for_ops(
        operations: Sequence[Any], fn: Callable[[BeaconState, Any], None]
    ) -> None:
        for operation in operations:
            fn(state, operation)

    for_ops(body.proposer_slashings, process_proposer_slashing)
    for_ops(body.attester_slashings, process_attester_slashing)
    # [Modified in Electra:EIP7549]
    for_ops(body.attestations, process_attestation)
    for_ops(body.deposits, process_deposit)
    # [Modified in Electra:EIP7251]
    for_ops(body.voluntary_exits, process_voluntary_exit)
    for_ops(body.bls_to_execution_changes, process_bls_to_execution_change)
    # [New in Electra:EIP6110]
    for_ops(body.execution_requests.deposits, process_deposit_request)
    # [New in Electra:EIP7002:EIP7251]
    for_ops(body.execution_requests.withdrawals, process_withdrawal_request)
    # [New in Electra:EIP7251]
    for_ops(body.execution_requests.consolidations, process_consolidation_request)


def process_proposer_slashing(
    state: BeaconState, proposer_slashing: ProposerSlashing
) -> None:
    header_1 = proposer_slashing.signed_header_1.message
    header_2 = proposer_slashing.signed_header_2.message

    # Verify header slots match
    assert header_1.slot == header_2.slot
    # Verify header proposer indices match
    assert header_1.proposer_index == header_2.proposer_index
    # Verify the headers are different
    assert header_1 != header_2
    # Verify the proposer is slashable
    proposer = state.validators[header_1.proposer_index]
    assert is_slashable_validator(proposer, get_current_epoch(state))
    # Verify signatures
    for signed_header in (
        proposer_slashing.signed_header_1,
        proposer_slashing.signed_header_2,
    ):
        domain = get_domain(
            state,
            DOMAIN_BEACON_PROPOSER,
            compute_epoch_at_slot(signed_header.message.slot),
        )
        signing_root = compute_signing_root(signed_header.message, domain)
        assert bls.Verify(proposer.pubkey, signing_root, signed_header.signature)

    slash_validator(state, header_1.proposer_index)


def process_attester_slashing(
    state: BeaconState, attester_slashing: AttesterSlashing
) -> None:
    attestation_1 = attester_slashing.attestation_1
    attestation_2 = attester_slashing.attestation_2
    assert is_slashable_attestation_data(attestation_1.data, attestation_2.data)
    assert is_valid_indexed_attestation(state, attestation_1)
    assert is_valid_indexed_attestation(state, attestation_2)

    slashed_any = False
    indices = set(attestation_1.attesting_indices).intersection(
        attestation_2.attesting_indices
    )
    for index in sorted(indices):
        if is_slashable_validator(state.validators[index], get_current_epoch(state)):
            slash_validator(state, index)
            slashed_any = True
    assert slashed_any


def process_attestation(state: BeaconState, attestation: Attestation) -> None:
    data = attestation.data
    assert data.target.epoch in (get_previous_epoch(state), get_current_epoch(state))
    assert data.target.epoch == compute_epoch_at_slot(data.slot)
    assert data.slot + MIN_ATTESTATION_INCLUSION_DELAY <= state.slot

    # [Modified in Electra:EIP7549]
    assert data.index == 0
    committee_indices = get_committee_indices(attestation.committee_bits)
    committee_offset = 0
    for committee_index in committee_indices:
        assert committee_index < get_committee_count_per_slot(state, data.target.epoch)
        committee = get_beacon_committee(state, data.slot, committee_index)
        committee_attesters = set(
            attester_index
            for i, attester_index in enumerate(committee)
            if attestation.aggregation_bits[committee_offset + i]
        )
        assert len(committee_attesters) > 0
        committee_offset += len(committee)

    # Bitfield length matches total number of participants
    assert len(attestation.aggregation_bits) == committee_offset

    # Participation flag indices
    participation_flag_indices = get_attestation_participation_flag_indices(
        state, data, state.slot - data.slot
    )

    # Verify signature
    assert is_valid_indexed_attestation(
        state, get_indexed_attestation(state, attestation)
    )

    # Update epoch participation flags
    if data.target.epoch == get_current_epoch(state):
        epoch_participation = state.current_epoch_participation
    else:
        epoch_participation = state.previous_epoch_participation

    proposer_reward_numerator = 0
    for index in get_attesting_indices(state, attestation):
        for flag_index, weight in enumerate(PARTICIPATION_FLAG_WEIGHTS):
            if flag_index in participation_flag_indices and not has_flag(
                epoch_participation[index], flag_index
            ):
                epoch_participation[index] = add_flag(
                    epoch_participation[index], flag_index
                )
                proposer_reward_numerator += get_base_reward(state, index) * weight

    # Reward proposer
    proposer_reward_denominator = (
        (WEIGHT_DENOMINATOR - PROPOSER_WEIGHT) * WEIGHT_DENOMINATOR // PROPOSER_WEIGHT
    )
    proposer_reward = Gwei(proposer_reward_numerator // proposer_reward_denominator)
    increase_balance(state, get_beacon_proposer_index(state), proposer_reward)


def process_voluntary_exit(
    state: BeaconState, signed_voluntary_exit: SignedVoluntaryExit
) -> None:
    voluntary_exit = signed_voluntary_exit.message
    validator = state.validators[voluntary_exit.validator_index]
    # Verify the validator is active
    assert is_active_validator(validator, get_current_epoch(state))
    # Verify exit has not been initiated
    assert validator.exit_epoch == FAR_FUTURE_EPOCH
    # Exits must specify an epoch when they become valid; they are not valid before then
    assert get_current_epoch(state) >= voluntary_exit.epoch
    # Verify the validator has been active long enough
    assert (
        get_current_epoch(state)
        >= validator.activation_epoch + config.SHARD_COMMITTEE_PERIOD
    )
    # [New in Electra:EIP7251]
    # Only exit validator if it has no pending withdrawals in the queue

    assert get_pending_balance_to_withdraw(state, voluntary_exit.validator_index) == 0
    # Verify signature
    domain = compute_domain(
        DOMAIN_VOLUNTARY_EXIT,
        config.CAPELLA_FORK_VERSION,
        state.genesis_validators_root,
    )
    signing_root = compute_signing_root(voluntary_exit, domain)
    assert bls.Verify(validator.pubkey, signing_root, signed_voluntary_exit.signature)
    # Initiate exit
    initiate_validator_exit(state, voluntary_exit.validator_index)


def process_sync_aggregate(state: BeaconState, sync_aggregate: SyncAggregate) -> None:
    # Verify sync committee aggregate signature signing over the previous slot block root
    committee_pubkeys = state.current_sync_committee.pubkeys
    participant_pubkeys = [
        pubkey
        for pubkey, bit in zip(committee_pubkeys, sync_aggregate.sync_committee_bits)
        if bit
    ]
    previous_slot = max(state.slot, Slot(1)) - Slot(1)
    domain = get_domain(
        state, DOMAIN_SYNC_COMMITTEE, compute_epoch_at_slot(previous_slot)
    )
    signing_root = compute_signing_root(
        get_block_root_at_slot(state, previous_slot), domain
    )
    assert eth_fast_aggregate_verify(
        participant_pubkeys, signing_root, sync_aggregate.sync_committee_signature
    )

    # Compute participant and proposer rewards
    total_active_increments = (
        get_total_active_balance(state) // EFFECTIVE_BALANCE_INCREMENT
    )
    total_base_rewards = Gwei(
        get_base_reward_per_increment(state) * total_active_increments
    )
    max_participant_rewards = Gwei(
        total_base_rewards * SYNC_REWARD_WEIGHT // WEIGHT_DENOMINATOR // SLOTS_PER_EPOCH
    )
    participant_reward = Gwei(max_participant_rewards // SYNC_COMMITTEE_SIZE)
    proposer_reward = Gwei(
        participant_reward * PROPOSER_WEIGHT // (WEIGHT_DENOMINATOR - PROPOSER_WEIGHT)
    )

    # Apply participant and proposer rewards
    all_pubkeys = [v.pubkey for v in state.validators]
    committee_indices = [
        ValidatorIndex(all_pubkeys.index(pubkey))
        for pubkey in state.current_sync_committee.pubkeys
    ]
    for participant_index, participation_bit in zip(
        committee_indices, sync_aggregate.sync_committee_bits
    ):
        if participation_bit:
            increase_balance(state, participant_index, participant_reward)
            increase_balance(state, get_beacon_proposer_index(state), proposer_reward)
        else:
            decrease_balance(state, participant_index, participant_reward)


def process_epoch(state: BeaconState) -> None:
    process_justification_and_finalization(state)
    process_inactivity_updates(state)
    process_rewards_and_penalties(state)
    # [Modified in Electra:EIP7251]
    process_registry_updates(state)
    # [Modified in Electra:EIP7251]
    process_slashings(state)
    process_eth1_data_reset(state)
    # [New in Electra:EIP7251]
    process_pending_deposits(state)
    # [New in Electra:EIP7251]
    process_pending_consolidations(state)
    # [Modified in Electra:EIP7251]
    process_effective_balance_updates(state)
    process_slashings_reset(state)
    process_randao_mixes_reset(state)
    process_historical_summaries_update(state)
    process_participation_flag_updates(state)
    process_sync_committee_updates(state)


def process_slashings(state: BeaconState) -> None:
    epoch = get_current_epoch(state)
    total_balance = get_total_active_balance(state)
    adjusted_total_slashing_balance = min(
        sum(state.slashings) * PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX, total_balance
    )
    increment = EFFECTIVE_BALANCE_INCREMENT  # Factored out from total balance to avoid uint64 overflow
    penalty_per_effective_balance_increment = adjusted_total_slashing_balance // (
        total_balance // increment
    )
    for index, validator in enumerate(state.validators):
        if (
            validator.slashed
            and epoch + EPOCHS_PER_SLASHINGS_VECTOR // 2 == validator.withdrawable_epoch
        ):
            effective_balance_increments = validator.effective_balance // increment
            # [Modified in Electra:EIP7251]
            penalty = (
                penalty_per_effective_balance_increment * effective_balance_increments
            )
            decrease_balance(state, ValidatorIndex(index), penalty)


def apply_pending_deposit(state: BeaconState, deposit: PendingDeposit) -> None:
    """
    Applies ``deposit`` to the ``state``.
    """
    validator_pubkeys = [v.pubkey for v in state.validators]
    if deposit.pubkey not in validator_pubkeys:
        # Verify the deposit signature (proof of possession) which is not checked by the deposit contract
        if is_valid_deposit_signature(
            deposit.pubkey,
            deposit.withdrawal_credentials,
            deposit.amount,
            deposit.signature,
        ):
            add_validator_to_registry(
                state, deposit.pubkey, deposit.withdrawal_credentials, deposit.amount
            )
    else:
        validator_index = ValidatorIndex(validator_pubkeys.index(deposit.pubkey))
        increase_balance(state, validator_index, deposit.amount)


def process_rewards_and_penalties(state: BeaconState) -> None:
    # No rewards are applied at the end of `GENESIS_EPOCH` because rewards are for work done in the previous epoch
    if get_current_epoch(state) == GENESIS_EPOCH:
        return

    flag_deltas = [
        get_flag_index_deltas(state, flag_index)
        for flag_index in range(len(PARTICIPATION_FLAG_WEIGHTS))
    ]
    deltas = flag_deltas + [get_inactivity_penalty_deltas(state)]
    for rewards, penalties in deltas:
        for index in range(len(state.validators)):
            increase_balance(state, ValidatorIndex(index), rewards[index])
            decrease_balance(state, ValidatorIndex(index), penalties[index])


def process_justification_and_finalization(state: BeaconState) -> None:
    # Initial FFG checkpoint values have a `0x00` stub for `root`.
    # Skip FFG updates in the first two epochs to avoid corner cases that might result in modifying this stub.
    if get_current_epoch(state) <= GENESIS_EPOCH + 1:
        return
    previous_indices = get_unslashed_participating_indices(
        state, TIMELY_TARGET_FLAG_INDEX, get_previous_epoch(state)
    )
    current_indices = get_unslashed_participating_indices(
        state, TIMELY_TARGET_FLAG_INDEX, get_current_epoch(state)
    )
    total_active_balance = get_total_active_balance(state)
    previous_target_balance = get_total_balance(state, previous_indices)
    current_target_balance = get_total_balance(state, current_indices)
    weigh_justification_and_finalization(
        state, total_active_balance, previous_target_balance, current_target_balance
    )


def upgrade_to_altair(pre: phase0.BeaconState) -> BeaconState:
    epoch = phase0.get_current_epoch(pre)
    post = BeaconState(
        genesis_time=pre.genesis_time,
        genesis_validators_root=pre.genesis_validators_root,
        slot=pre.slot,
        fork=Fork(
            previous_version=pre.fork.current_version,
            current_version=config.ALTAIR_FORK_VERSION,
            epoch=epoch,
        ),
        latest_block_header=pre.latest_block_header,
        block_roots=pre.block_roots,
        state_roots=pre.state_roots,
        historical_roots=pre.historical_roots,
        eth1_data=pre.eth1_data,
        eth1_data_votes=pre.eth1_data_votes,
        eth1_deposit_index=pre.eth1_deposit_index,
        validators=pre.validators,
        balances=pre.balances,
        randao_mixes=pre.randao_mixes,
        slashings=pre.slashings,
        previous_epoch_participation=[
            ParticipationFlags(0b0000_0000) for _ in range(len(pre.validators))
        ],
        current_epoch_participation=[
            ParticipationFlags(0b0000_0000) for _ in range(len(pre.validators))
        ],
        justification_bits=pre.justification_bits,
        previous_justified_checkpoint=pre.previous_justified_checkpoint,
        current_justified_checkpoint=pre.current_justified_checkpoint,
        finalized_checkpoint=pre.finalized_checkpoint,
        inactivity_scores=[uint64(0) for _ in range(len(pre.validators))],
    )
    # Fill in previous epoch participation from the pre state's pending attestations
    translate_participation(post, pre.previous_epoch_attestations)

    # Fill in sync committees
    # Note: A duplicate committee is assigned for the current and next committee at the fork boundary
    post.current_sync_committee = get_next_sync_committee(post)
    post.next_sync_committee = get_next_sync_committee(post)
    return post


############## 直接的: validatorとそのfield (それより上位はない) ##############


def process_bls_to_execution_change(
    state: BeaconState, signed_address_change: SignedBLSToExecutionChange
) -> None:
    address_change = signed_address_change.message

    assert address_change.validator_index < len(state.validators)

    validator = state.validators[address_change.validator_index]

    assert validator.withdrawal_credentials[:1] == BLS_WITHDRAWAL_PREFIX
    assert (
        validator.withdrawal_credentials[1:] == hash(address_change.from_bls_pubkey)[1:]
    )

    # Fork-agnostic domain since address changes are valid across forks
    domain = compute_domain(
        DOMAIN_BLS_TO_EXECUTION_CHANGE,
        genesis_validators_root=state.genesis_validators_root,
    )
    signing_root = compute_signing_root(address_change, domain)
    assert bls.Verify(
        address_change.from_bls_pubkey, signing_root, signed_address_change.signature
    )

    validator.withdrawal_credentials = (
        ETH1_ADDRESS_WITHDRAWAL_PREFIX
        + b"\x00" * 11
        + address_change.to_execution_address
    )


############## 直接的: stateとそのfield ##############


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


# 例外的に`set_or_append_list`越しに更新
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


def translate_participation(
    state: BeaconState, pending_attestations: Sequence[phase0.PendingAttestation]
) -> None:
    for attestation in pending_attestations:
        data = attestation.data
        inclusion_delay = attestation.inclusion_delay
        # Translate attestation inclusion info to flag indices
        participation_flag_indices = get_attestation_participation_flag_indices(
            state, data, inclusion_delay
        )

        # Apply flags to all attesting validators
        epoch_participation = state.previous_epoch_participation
        for index in get_attesting_indices(state, attestation):
            for flag_index in participation_flag_indices:
                epoch_participation[index] = add_flag(
                    epoch_participation[index], flag_index
                )


def process_pending_consolidations(state: BeaconState) -> None:
    next_epoch = Epoch(get_current_epoch(state) + 1)
    next_pending_consolidation = 0
    for pending_consolidation in state.pending_consolidations:
        source_validator = state.validators[pending_consolidation.source_index]
        if source_validator.slashed:
            next_pending_consolidation += 1
            continue
        if source_validator.withdrawable_epoch > next_epoch:
            break

        # Calculate the consolidated balance
        source_effective_balance = min(
            state.balances[pending_consolidation.source_index],
            source_validator.effective_balance,
        )

        # Move active balance to target. Excess balance is withdrawable.
        decrease_balance(
            state, pending_consolidation.source_index, source_effective_balance
        )
        increase_balance(
            state, pending_consolidation.target_index, source_effective_balance
        )
        next_pending_consolidation += 1

    state.pending_consolidations = state.pending_consolidations[
        next_pending_consolidation:
    ]


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


def process_execution_payload(
    state: BeaconState, body: BeaconBlockBody, execution_engine: ExecutionEngine
) -> None:
    payload = body.execution_payload

    # Verify consistency of the parent hash with respect to the previous execution payload header
    assert payload.parent_hash == state.latest_execution_payload_header.block_hash
    # Verify prev_randao
    assert payload.prev_randao == get_randao_mix(state, get_current_epoch(state))
    # Verify timestamp
    assert payload.timestamp == compute_timestamp_at_slot(state, state.slot)
    # [Modified in Electra:EIP7691] Verify commitments are under limit
    assert len(body.blob_kzg_commitments) <= config.MAX_BLOBS_PER_BLOCK_ELECTRA
    # Verify the execution payload is valid
    versioned_hashes = [
        kzg_commitment_to_versioned_hash(commitment)
        for commitment in body.blob_kzg_commitments
    ]
    assert execution_engine.verify_and_notify_new_payload(
        NewPayloadRequest(
            execution_payload=payload,
            versioned_hashes=versioned_hashes,
            parent_beacon_block_root=state.latest_block_header.parent_root,
            # [New in Electra]
            execution_requests=body.execution_requests,
        )
    )
    # Cache execution payload header
    state.latest_execution_payload_header = ExecutionPayloadHeader(
        parent_hash=payload.parent_hash,
        fee_recipient=payload.fee_recipient,
        state_root=payload.state_root,
        receipts_root=payload.receipts_root,
        logs_bloom=payload.logs_bloom,
        prev_randao=payload.prev_randao,
        block_number=payload.block_number,
        gas_limit=payload.gas_limit,
        gas_used=payload.gas_used,
        timestamp=payload.timestamp,
        extra_data=payload.extra_data,
        base_fee_per_gas=payload.base_fee_per_gas,
        block_hash=payload.block_hash,
        transactions_root=hash_tree_root(payload.transactions),
        withdrawals_root=hash_tree_root(payload.withdrawals),
        blob_gas_used=payload.blob_gas_used,
        excess_blob_gas=payload.excess_blob_gas,
    )


############## 直接的: 未分類 ##############


def process_pending_deposits(state: BeaconState) -> None:
    next_epoch = Epoch(get_current_epoch(state) + 1)
    available_for_processing = (
        state.deposit_balance_to_consume + get_activation_exit_churn_limit(state)
    )
    processed_amount = 0
    next_deposit_index = 0
    deposits_to_postpone = []
    is_churn_limit_reached = False
    finalized_slot = compute_start_slot_at_epoch(state.finalized_checkpoint.epoch)

    for deposit in state.pending_deposits:
        # Do not process deposit requests if Eth1 bridge deposits are not yet applied.
        if (
            # Is deposit request
            deposit.slot > GENESIS_SLOT
            and
            # There are pending Eth1 bridge deposits
            state.eth1_deposit_index < state.deposit_requests_start_index
        ):
            break

        # Check if deposit has been finalized, otherwise, stop processing.
        if deposit.slot > finalized_slot:
            break

        # Check if number of processed deposits has not reached the limit, otherwise, stop processing.
        if next_deposit_index >= MAX_PENDING_DEPOSITS_PER_EPOCH:
            break

        # Read validator state
        is_validator_exited = False
        is_validator_withdrawn = False
        validator_pubkeys = [v.pubkey for v in state.validators]
        if deposit.pubkey in validator_pubkeys:
            validator = state.validators[
                ValidatorIndex(validator_pubkeys.index(deposit.pubkey))
            ]
            is_validator_exited = validator.exit_epoch < FAR_FUTURE_EPOCH
            is_validator_withdrawn = validator.withdrawable_epoch < next_epoch

        if is_validator_withdrawn:
            # Deposited balance will never become active. Increase balance but do not consume churn
            apply_pending_deposit(state, deposit)
        elif is_validator_exited:
            # Validator is exiting, postpone the deposit until after withdrawable epoch
            deposits_to_postpone.append(deposit)
        else:
            # Check if deposit fits in the churn, otherwise, do no more deposit processing in this epoch.
            is_churn_limit_reached = (
                processed_amount + deposit.amount > available_for_processing
            )
            if is_churn_limit_reached:
                break

            # Consume churn and apply deposit.
            processed_amount += deposit.amount
            apply_pending_deposit(state, deposit)

        # Regardless of how the deposit was handled, we move on in the queue.
        next_deposit_index += 1

    state.pending_deposits = (
        state.pending_deposits[next_deposit_index:] + deposits_to_postpone
    )

    # Accumulate churn only if the churn limit has been hit.
    if is_churn_limit_reached:
        state.deposit_balance_to_consume = available_for_processing - processed_amount
    else:
        state.deposit_balance_to_consume = Gwei(0)


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


def process_deposit_request(
    state: BeaconState, deposit_request: DepositRequest
) -> None:
    # Set deposit request start index
    if state.deposit_requests_start_index == UNSET_DEPOSIT_REQUESTS_START_INDEX:
        state.deposit_requests_start_index = deposit_request.index

    # Create pending deposit
    state.pending_deposits.append(
        PendingDeposit(
            pubkey=deposit_request.pubkey,
            withdrawal_credentials=deposit_request.withdrawal_credentials,
            amount=deposit_request.amount,
            signature=deposit_request.signature,
            slot=state.slot,
        )
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


def process_withdrawals(state: BeaconState, payload: ExecutionPayload) -> None:
    # [Modified in Electra:EIP7251]
    expected_withdrawals, processed_partial_withdrawals_count = (
        get_expected_withdrawals(state)
    )

    assert payload.withdrawals == expected_withdrawals

    for withdrawal in expected_withdrawals:
        decrease_balance(state, withdrawal.validator_index, withdrawal.amount)

    # [New in Electra:EIP7251] Update pending partial withdrawals
    state.pending_partial_withdrawals = state.pending_partial_withdrawals[
        processed_partial_withdrawals_count:
    ]

    # Update the next withdrawal index if this block contained withdrawals
    if len(expected_withdrawals) != 0:
        latest_withdrawal = expected_withdrawals[-1]
        state.next_withdrawal_index = WithdrawalIndex(latest_withdrawal.index + 1)

    # Update the next validator index to start the next withdrawal sweep
    if len(expected_withdrawals) == MAX_WITHDRAWALS_PER_PAYLOAD:
        # Next sweep starts after the latest withdrawal's validator index
        next_validator_index = ValidatorIndex(
            (expected_withdrawals[-1].validator_index + 1) % len(state.validators)
        )
        state.next_withdrawal_validator_index = next_validator_index
    else:
        # Advance sweep by the max length of the sweep if there was not a full set of withdrawals
        next_index = (
            state.next_withdrawal_validator_index + MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP
        )
        next_validator_index = ValidatorIndex(next_index % len(state.validators))
        state.next_withdrawal_validator_index = next_validator_index


def initialize_beacon_state_from_eth1(
    eth1_block_hash: Hash32, eth1_timestamp: uint64, deposits: Sequence[Deposit]
) -> BeaconState:
    fork = Fork(
        previous_version=config.GENESIS_FORK_VERSION,
        current_version=config.GENESIS_FORK_VERSION,
        epoch=GENESIS_EPOCH,
    )
    state = BeaconState(
        genesis_time=eth1_timestamp + config.GENESIS_DELAY,
        fork=fork,
        eth1_data=Eth1Data(
            block_hash=eth1_block_hash, deposit_count=uint64(len(deposits))
        ),
        latest_block_header=BeaconBlockHeader(
            body_root=hash_tree_root(BeaconBlockBody())
        ),
        randao_mixes=[eth1_block_hash]
        * EPOCHS_PER_HISTORICAL_VECTOR,  # Seed RANDAO with Eth1 entropy
    )

    # Process deposits
    leaves = list(map(lambda deposit: deposit.data, deposits))
    for index, deposit in enumerate(deposits):
        deposit_data_list = List[DepositData, 2**DEPOSIT_CONTRACT_TREE_DEPTH](
            *leaves[: index + 1]
        )
        state.eth1_data.deposit_root = hash_tree_root(deposit_data_list)
        process_deposit(state, deposit)

    # Process activations
    for index, validator in enumerate(state.validators):
        balance = state.balances[index]
        validator.effective_balance = min(
            balance - balance % EFFECTIVE_BALANCE_INCREMENT, MAX_EFFECTIVE_BALANCE
        )
        if validator.effective_balance == MAX_EFFECTIVE_BALANCE:
            validator.activation_eligibility_epoch = GENESIS_EPOCH
            validator.activation_epoch = GENESIS_EPOCH

    # Set genesis validators root for domain separation and chain versioning
    state.genesis_validators_root = hash_tree_root(state.validators)

    return state


def process_slots(state: BeaconState, slot: Slot) -> None:
    assert state.slot < slot
    while state.slot < slot:
        process_slot(state)
        # Process epoch on the start slot of the next epoch
        if (state.slot + 1) % SLOTS_PER_EPOCH == 0:
            process_epoch(state)
        state.slot = Slot(state.slot + 1)


def process_slot(state: BeaconState) -> None:
    # Cache state root
    previous_state_root = hash_tree_root(state)
    state.state_roots[state.slot % SLOTS_PER_HISTORICAL_ROOT] = previous_state_root
    # Cache latest block header state root
    if state.latest_block_header.state_root == Bytes32():
        state.latest_block_header.state_root = previous_state_root
    # Cache block root
    previous_block_root = hash_tree_root(state.latest_block_header)
    state.block_roots[state.slot % SLOTS_PER_HISTORICAL_ROOT] = previous_block_root


def process_deposit(state: BeaconState, deposit: Deposit) -> None:
    # Verify the Merkle branch
    assert is_valid_merkle_branch(
        leaf=hash_tree_root(deposit.data),
        branch=deposit.proof,
        # Add 1 for the List length mix-in
        depth=DEPOSIT_CONTRACT_TREE_DEPTH + 1,
        index=state.eth1_deposit_index,
        root=state.eth1_data.deposit_root,
    )

    # Deposits must be processed in order
    state.eth1_deposit_index += 1

    # [Modified in Electra:EIP7251]
    apply_deposit(
        state=state,
        pubkey=deposit.data.pubkey,
        withdrawal_credentials=deposit.data.withdrawal_credentials,
        amount=deposit.data.amount,
        signature=deposit.data.signature,
    )


def apply_deposit(
    state: BeaconState,
    pubkey: BLSPubkey,
    withdrawal_credentials: Bytes32,
    amount: uint64,
    signature: BLSSignature,
) -> None:
    validator_pubkeys = [v.pubkey for v in state.validators]
    if pubkey not in validator_pubkeys:
        # Verify the deposit signature (proof of possession) which is not checked by the deposit contract
        if is_valid_deposit_signature(
            pubkey, withdrawal_credentials, amount, signature
        ):
            # [Modified in Electra:EIP7251]
            add_validator_to_registry(state, pubkey, withdrawal_credentials, Gwei(0))
        else:
            return

    # [Modified in Electra:EIP7251]
    # Increase balance by deposit amount
    state.pending_deposits.append(
        PendingDeposit(
            pubkey=pubkey,
            withdrawal_credentials=withdrawal_credentials,
            amount=amount,
            signature=signature,
            slot=GENESIS_SLOT,  # Use GENESIS_SLOT to distinguish from a pending deposit request
        )
    )


def process_inactivity_updates(state: BeaconState) -> None:
    # Skip the genesis epoch as score updates are based on the previous epoch participation
    if get_current_epoch(state) == GENESIS_EPOCH:
        return

    for index in get_eligible_validator_indices(state):
        # Increase the inactivity score of inactive validators
        if index in get_unslashed_participating_indices(
            state, TIMELY_TARGET_FLAG_INDEX, get_previous_epoch(state)
        ):
            state.inactivity_scores[index] -= min(1, state.inactivity_scores[index])
        else:
            state.inactivity_scores[index] += config.INACTIVITY_SCORE_BIAS
        # Decrease the inactivity score of all eligible validators during a leak-free epoch
        if not is_in_inactivity_leak(state):
            state.inactivity_scores[index] -= min(
                config.INACTIVITY_SCORE_RECOVERY_RATE, state.inactivity_scores[index]
            )


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


def process_registry_updates(state: BeaconState) -> None:
    current_epoch = get_current_epoch(state)
    activation_epoch = compute_activation_exit_epoch(current_epoch)

    # Process activation eligibility, ejections, and activations
    for index, validator in enumerate(state.validators):
        if is_eligible_for_activation_queue(validator):  # [Modified in Electra:EIP7251]
            validator.activation_eligibility_epoch = current_epoch + 1
        elif (
            is_active_validator(validator, current_epoch)
            and validator.effective_balance <= config.EJECTION_BALANCE
        ):
            initiate_validator_exit(
                state, ValidatorIndex(index)
            )  # [Modified in Electra:EIP7251]
        elif is_eligible_for_activation(state, validator):
            validator.activation_epoch = activation_epoch


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


def process_eth1_data_reset(state: BeaconState) -> None:
    next_epoch = Epoch(get_current_epoch(state) + 1)
    # Reset eth1 data votes
    if next_epoch % EPOCHS_PER_ETH1_VOTING_PERIOD == 0:
        state.eth1_data_votes = []


def process_effective_balance_updates(state: BeaconState) -> None:
    # Update effective balances with hysteresis
    for index, validator in enumerate(state.validators):
        balance = state.balances[index]
        HYSTERESIS_INCREMENT = uint64(
            EFFECTIVE_BALANCE_INCREMENT // HYSTERESIS_QUOTIENT
        )
        DOWNWARD_THRESHOLD = HYSTERESIS_INCREMENT * HYSTERESIS_DOWNWARD_MULTIPLIER
        UPWARD_THRESHOLD = HYSTERESIS_INCREMENT * HYSTERESIS_UPWARD_MULTIPLIER
        # [Modified in Electra:EIP7251]
        max_effective_balance = get_max_effective_balance(validator)

        if (
            balance + DOWNWARD_THRESHOLD < validator.effective_balance
            or validator.effective_balance + UPWARD_THRESHOLD < balance
        ):
            validator.effective_balance = min(
                balance - balance % EFFECTIVE_BALANCE_INCREMENT, max_effective_balance
            )


def process_slashings_reset(state: BeaconState) -> None:
    next_epoch = Epoch(get_current_epoch(state) + 1)
    # Reset slashings
    state.slashings[next_epoch % EPOCHS_PER_SLASHINGS_VECTOR] = Gwei(0)


def process_randao_mixes_reset(state: BeaconState) -> None:
    current_epoch = get_current_epoch(state)
    next_epoch = Epoch(current_epoch + 1)
    # Set randao mix
    state.randao_mixes[next_epoch % EPOCHS_PER_HISTORICAL_VECTOR] = get_randao_mix(
        state, current_epoch
    )


def process_historical_summaries_update(state: BeaconState) -> None:
    # Set historical block root accumulator.
    next_epoch = Epoch(get_current_epoch(state) + 1)
    if next_epoch % (SLOTS_PER_HISTORICAL_ROOT // SLOTS_PER_EPOCH) == 0:
        historical_summary = HistoricalSummary(
            block_summary_root=hash_tree_root(state.block_roots),
            state_summary_root=hash_tree_root(state.state_roots),
        )
        state.historical_summaries.append(historical_summary)


def process_participation_flag_updates(state: BeaconState) -> None:
    state.previous_epoch_participation = state.current_epoch_participation
    state.current_epoch_participation = [
        ParticipationFlags(0b0000_0000) for _ in range(len(state.validators))
    ]


def process_sync_committee_updates(state: BeaconState) -> None:
    next_epoch = get_current_epoch(state) + Epoch(1)
    if next_epoch % EPOCHS_PER_SYNC_COMMITTEE_PERIOD == 0:
        state.current_sync_committee = state.next_sync_committee
        state.next_sync_committee = get_next_sync_committee(state)


def process_participation_record_updates(state: BeaconState) -> None:
    # Rotate current/previous epoch attestations
    state.previous_epoch_attestations = state.current_epoch_attestations
    state.current_epoch_attestations = []


def process_block_header(state: BeaconState, block: BeaconBlock) -> None:
    # Verify that the slots match
    assert block.slot == state.slot
    # Verify that the block is newer than latest block header
    assert block.slot > state.latest_block_header.slot
    # Verify that proposer index is the correct index
    assert block.proposer_index == get_beacon_proposer_index(state)
    # Verify that the parent matches
    assert block.parent_root == hash_tree_root(state.latest_block_header)
    # Cache current block as the new latest block
    state.latest_block_header = BeaconBlockHeader(
        slot=block.slot,
        proposer_index=block.proposer_index,
        parent_root=block.parent_root,
        state_root=Bytes32(),  # Overwritten in the next process_slot call
        body_root=hash_tree_root(block.body),
    )

    # Verify proposer is not slashed
    proposer = state.validators[block.proposer_index]
    assert not proposer.slashed


def process_randao(state: BeaconState, body: BeaconBlockBody) -> None:
    epoch = get_current_epoch(state)
    # Verify RANDAO reveal
    proposer = state.validators[get_beacon_proposer_index(state)]
    signing_root = compute_signing_root(epoch, get_domain(state, DOMAIN_RANDAO))
    assert bls.Verify(proposer.pubkey, signing_root, body.randao_reveal)
    # Mix in RANDAO reveal
    mix = xor(get_randao_mix(state, epoch), hash(body.randao_reveal))
    state.randao_mixes[epoch % EPOCHS_PER_HISTORICAL_VECTOR] = mix


def process_eth1_data(state: BeaconState, body: BeaconBlockBody) -> None:
    state.eth1_data_votes.append(body.eth1_data)
    if (
        state.eth1_data_votes.count(body.eth1_data) * 2
        > EPOCHS_PER_ETH1_VOTING_PERIOD * SLOTS_PER_EPOCH
    ):
        state.eth1_data = body.eth1_data


def process_historical_roots_update(state: BeaconState) -> None:
    # Set historical root accumulator
    next_epoch = Epoch(get_current_epoch(state) + 1)
    if next_epoch % (SLOTS_PER_HISTORICAL_ROOT // SLOTS_PER_EPOCH) == 0:
        historical_batch = HistoricalBatch(
            block_roots=state.block_roots, state_roots=state.state_roots
        )
        state.historical_roots.append(hash_tree_root(historical_batch))


def process_withdrawal_request(
    state: BeaconState, withdrawal_request: WithdrawalRequest
) -> None:
    amount = withdrawal_request.amount
    is_full_exit_request = amount == FULL_EXIT_REQUEST_AMOUNT

    # If partial withdrawal queue is full, only full exits are processed
    if (
        len(state.pending_partial_withdrawals) == PENDING_PARTIAL_WITHDRAWALS_LIMIT
        and not is_full_exit_request
    ):
        return

    validator_pubkeys = [v.pubkey for v in state.validators]
    # Verify pubkey exists
    request_pubkey = withdrawal_request.validator_pubkey
    if request_pubkey not in validator_pubkeys:
        return
    index = ValidatorIndex(validator_pubkeys.index(request_pubkey))
    validator = state.validators[index]

    # Verify withdrawal credentials
    has_correct_credential = has_execution_withdrawal_credential(validator)
    is_correct_source_address = (
        validator.withdrawal_credentials[12:] == withdrawal_request.source_address
    )
    if not (has_correct_credential and is_correct_source_address):
        return
    # Verify the validator is active
    if not is_active_validator(validator, get_current_epoch(state)):
        return
    # Verify exit has not been initiated
    if validator.exit_epoch != FAR_FUTURE_EPOCH:
        return
    # Verify the validator has been active long enough
    if (
        get_current_epoch(state)
        < validator.activation_epoch + config.SHARD_COMMITTEE_PERIOD
    ):
        return

    pending_balance_to_withdraw = get_pending_balance_to_withdraw(state, index)

    if is_full_exit_request:
        # Only exit validator if it has no pending withdrawals in the queue
        if pending_balance_to_withdraw == 0:
            initiate_validator_exit(state, index)
        return

    has_sufficient_effective_balance = (
        validator.effective_balance >= MIN_ACTIVATION_BALANCE
    )
    has_excess_balance = (
        state.balances[index] > MIN_ACTIVATION_BALANCE + pending_balance_to_withdraw
    )

    # Only allow partial withdrawals with compounding withdrawal credentials
    if (
        has_compounding_withdrawal_credential(validator)
        and has_sufficient_effective_balance
        and has_excess_balance
    ):
        to_withdraw = min(
            state.balances[index]
            - MIN_ACTIVATION_BALANCE
            - pending_balance_to_withdraw,
            amount,
        )
        exit_queue_epoch = compute_exit_epoch_and_update_churn(state, to_withdraw)
        withdrawable_epoch = Epoch(
            exit_queue_epoch + config.MIN_VALIDATOR_WITHDRAWABILITY_DELAY
        )
        state.pending_partial_withdrawals.append(
            PendingPartialWithdrawal(
                validator_index=index,
                amount=to_withdraw,
                withdrawable_epoch=withdrawable_epoch,
            )
        )


def process_consolidation_request(
    state: BeaconState, consolidation_request: ConsolidationRequest
) -> None:
    if is_valid_switch_to_compounding_request(state, consolidation_request):
        validator_pubkeys = [v.pubkey for v in state.validators]
        request_source_pubkey = consolidation_request.source_pubkey
        source_index = ValidatorIndex(validator_pubkeys.index(request_source_pubkey))
        switch_to_compounding_validator(state, source_index)
        return

    # Verify that source != target, so a consolidation cannot be used as an exit
    if consolidation_request.source_pubkey == consolidation_request.target_pubkey:
        return
    # If the pending consolidations queue is full, consolidation requests are ignored
    if len(state.pending_consolidations) == PENDING_CONSOLIDATIONS_LIMIT:
        return
    # If there is too little available consolidation churn limit, consolidation requests are ignored
    if get_consolidation_churn_limit(state) <= MIN_ACTIVATION_BALANCE:
        return

    validator_pubkeys = [v.pubkey for v in state.validators]
    # Verify pubkeys exists
    request_source_pubkey = consolidation_request.source_pubkey
    request_target_pubkey = consolidation_request.target_pubkey
    if request_source_pubkey not in validator_pubkeys:
        return
    if request_target_pubkey not in validator_pubkeys:
        return
    source_index = ValidatorIndex(validator_pubkeys.index(request_source_pubkey))
    target_index = ValidatorIndex(validator_pubkeys.index(request_target_pubkey))
    source_validator = state.validators[source_index]
    target_validator = state.validators[target_index]

    # Verify source withdrawal credentials
    has_correct_credential = has_execution_withdrawal_credential(source_validator)
    is_correct_source_address = (
        source_validator.withdrawal_credentials[12:]
        == consolidation_request.source_address
    )
    if not (has_correct_credential and is_correct_source_address):
        return

    # Verify that target has compounding withdrawal credentials
    if not has_compounding_withdrawal_credential(target_validator):
        return

    # Verify the source and the target are active
    current_epoch = get_current_epoch(state)
    if not is_active_validator(source_validator, current_epoch):
        return
    if not is_active_validator(target_validator, current_epoch):
        return
    # Verify exits for source and target have not been initiated
    if source_validator.exit_epoch != FAR_FUTURE_EPOCH:
        return
    if target_validator.exit_epoch != FAR_FUTURE_EPOCH:
        return
    # Verify the source has been active long enough
    if (
        current_epoch
        < source_validator.activation_epoch + config.SHARD_COMMITTEE_PERIOD
    ):
        return
    # Verify the source has no pending withdrawals in the queue
    if get_pending_balance_to_withdraw(state, source_index) > 0:
        return

    # Initiate source validator exit and append pending consolidation
    source_validator.exit_epoch = compute_consolidation_epoch_and_update_churn(
        state, source_validator.effective_balance
    )
    source_validator.withdrawable_epoch = Epoch(
        source_validator.exit_epoch + config.MIN_VALIDATOR_WITHDRAWABILITY_DELAY
    )
    state.pending_consolidations.append(
        PendingConsolidation(source_index=source_index, target_index=target_index)
    )


def switch_to_compounding_validator(state: BeaconState, index: ValidatorIndex) -> None:
    validator = state.validators[index]
    validator.withdrawal_credentials = (
        COMPOUNDING_WITHDRAWAL_PREFIX + validator.withdrawal_credentials[1:]
    )
    queue_excess_active_balance(state, index)


def slash_validator(
    state: BeaconState,
    slashed_index: ValidatorIndex,
    whistleblower_index: ValidatorIndex = None,
) -> None:
    """
    Slash the validator with index ``slashed_index``.
    """
    epoch = get_current_epoch(state)
    initiate_validator_exit(state, slashed_index)
    validator = state.validators[slashed_index]
    validator.slashed = True
    validator.withdrawable_epoch = max(
        validator.withdrawable_epoch, Epoch(epoch + EPOCHS_PER_SLASHINGS_VECTOR)
    )
    state.slashings[epoch % EPOCHS_PER_SLASHINGS_VECTOR] += validator.effective_balance
    # [Modified in Electra:EIP7251]
    slashing_penalty = (
        validator.effective_balance // MIN_SLASHING_PENALTY_QUOTIENT_ELECTRA
    )
    decrease_balance(state, slashed_index, slashing_penalty)

    # Apply proposer and whistleblower rewards
    proposer_index = get_beacon_proposer_index(state)
    if whistleblower_index is None:
        whistleblower_index = proposer_index
    # [Modified in Electra:EIP7251]
    whistleblower_reward = Gwei(
        validator.effective_balance // WHISTLEBLOWER_REWARD_QUOTIENT_ELECTRA
    )
    proposer_reward = Gwei(whistleblower_reward * PROPOSER_WEIGHT // WEIGHT_DENOMINATOR)
    increase_balance(state, proposer_index, proposer_reward)
    increase_balance(
        state, whistleblower_index, Gwei(whistleblower_reward - proposer_reward)
    )

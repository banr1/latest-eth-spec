from typing import Any, Callable

from eth2spec.latest.constants_0 import *
from eth2spec.latest.funcs_0 import *
from eth2spec.latest.classes_0 import *
from eth2spec.latest.constants_1 import *
from eth2spec.latest.classes_1 import *
from eth2spec.latest.funcs_1 import *
from eth2spec.latest.funcs_2_write_state import *
from eth2spec.latest.funcs_2_read_store import *
from eth2spec.latest.funcs_2_read_state import *


EXECUTION_ENGINE = NoopExecutionEngine()


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


def is_slashable_validator(validator: Validator, epoch: Epoch) -> bool:
    """
    Check if ``validator`` is slashable.
    """
    return (not validator.slashed) and (
        validator.activation_epoch <= epoch < validator.withdrawable_epoch
    )


def is_valid_indexed_attestation(
    state: BeaconState, indexed_attestation: IndexedAttestation
) -> bool:
    """
    Check if ``indexed_attestation`` is not empty, has sorted and unique indices and has a valid aggregate signature.
    """
    # Verify indices are sorted and unique
    indices = indexed_attestation.attesting_indices
    if len(indices) == 0 or not indices == sorted(set(indices)):
        return False
    # Verify aggregate signature
    pubkeys = [state.validators[i].pubkey for i in indices]
    domain = get_domain(
        state, DOMAIN_BEACON_ATTESTER, indexed_attestation.data.target.epoch
    )
    signing_root = compute_signing_root(indexed_attestation.data, domain)
    return bls.FastAggregateVerify(pubkeys, signing_root, indexed_attestation.signature)


def is_valid_switch_to_compounding_request(
    state: BeaconState, consolidation_request: ConsolidationRequest
) -> bool:
    # Switch to compounding requires source and target be equal
    if consolidation_request.source_pubkey != consolidation_request.target_pubkey:
        return False

    # Verify pubkey exists
    source_pubkey = consolidation_request.source_pubkey
    validator_pubkeys = [v.pubkey for v in state.validators]
    if source_pubkey not in validator_pubkeys:
        return False

    source_validator = state.validators[
        ValidatorIndex(validator_pubkeys.index(source_pubkey))
    ]

    # Verify request has been authorized
    if (
        source_validator.withdrawal_credentials[12:]
        != consolidation_request.source_address
    ):
        return False

    # Verify source withdrawal credentials
    if not has_eth1_withdrawal_credential(source_validator):
        return False

    # Verify the source is active
    current_epoch = get_current_epoch(state)
    if not is_active_validator(source_validator, current_epoch):
        return False

    # Verify exit for source has not been initiated
    if source_validator.exit_epoch != FAR_FUTURE_EPOCH:
        return False

    return True


def switch_to_compounding_validator(state: BeaconState, index: ValidatorIndex) -> None:
    validator = state.validators[index]
    validator.withdrawal_credentials = (
        COMPOUNDING_WITHDRAWAL_PREFIX + validator.withdrawal_credentials[1:]
    )
    queue_excess_active_balance(state, index)


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


def get_attestation_participation_flag_indices(
    state: BeaconState, data: AttestationData, inclusion_delay: uint64
) -> Sequence[int]:
    """
    Return the flag indices that are satisfied by an attestation.
    """
    if data.target.epoch == get_current_epoch(state):
        justified_checkpoint = state.current_justified_checkpoint
    else:
        justified_checkpoint = state.previous_justified_checkpoint

    # Matching roots
    is_matching_source = data.source == justified_checkpoint
    is_matching_target = is_matching_source and data.target.root == get_block_root(
        state, data.target.epoch
    )
    is_matching_head = (
        is_matching_target
        and data.beacon_block_root == get_block_root_at_slot(state, data.slot)
    )
    assert is_matching_source

    participation_flag_indices = []
    if is_matching_source and inclusion_delay <= integer_squareroot(SLOTS_PER_EPOCH):
        participation_flag_indices.append(TIMELY_SOURCE_FLAG_INDEX)
    if is_matching_target:  # [Modified in Deneb:EIP7045]
        participation_flag_indices.append(TIMELY_TARGET_FLAG_INDEX)
    if is_matching_head and inclusion_delay == MIN_ATTESTATION_INCLUSION_DELAY:
        participation_flag_indices.append(TIMELY_HEAD_FLAG_INDEX)

    return participation_flag_indices


def get_indexed_attestation(
    state: BeaconState, attestation: Attestation
) -> IndexedAttestation:
    """
    Return the indexed attestation corresponding to ``attestation``.
    """
    attesting_indices = get_attesting_indices(state, attestation)

    return IndexedAttestation(
        attesting_indices=sorted(attesting_indices),
        data=attestation.data,
        signature=attestation.signature,
    )


def add_flag(flags: ParticipationFlags, flag_index: int) -> ParticipationFlags:
    """
    Return a new ``ParticipationFlags`` adding ``flag_index`` to ``flags``.
    """
    flag = ParticipationFlags(2**flag_index)
    return flags | flag


def is_slashable_attestation_data(
    data_1: AttestationData, data_2: AttestationData
) -> bool:
    """
    Check if ``data_1`` and ``data_2`` are slashable according to Casper FFG rules.
    """
    return (
        # Double vote
        (data_1 != data_2 and data_1.target.epoch == data_2.target.epoch)
        or
        # Surround vote
        (
            data_1.source.epoch < data_2.source.epoch
            and data_2.target.epoch < data_1.target.epoch
        )
    )


def kzg_commitment_to_versioned_hash(kzg_commitment: KZGCommitment) -> VersionedHash:
    return VERSIONED_HASH_VERSION_KZG + hash(kzg_commitment)[1:]


def eth_fast_aggregate_verify(
    pubkeys: Sequence[BLSPubkey], message: Bytes32, signature: BLSSignature
) -> bool:
    """
    Wrapper to ``bls.FastAggregateVerify`` accepting the ``G2_POINT_AT_INFINITY`` signature when ``pubkeys`` is empty.
    """
    if len(pubkeys) == 0 and signature == G2_POINT_AT_INFINITY:
        return True
    return bls.FastAggregateVerify(pubkeys, message, signature)


def xor(bytes_1: Bytes32, bytes_2: Bytes32) -> Bytes32:
    """
    Return the exclusive-or of two 32-byte strings.
    """
    return Bytes32(a ^ b for a, b in zip(bytes_1, bytes_2))

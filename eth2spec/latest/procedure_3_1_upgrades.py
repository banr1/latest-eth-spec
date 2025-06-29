from eth2spec.utils.ssz.ssz_impl import hash_tree_root, copy

from eth2spec.phase0 import mainnet as phase0
from eth2spec.altair import mainnet as altair
from eth2spec.bellatrix import mainnet as bellatrix
from eth2spec.capella import mainnet as capella
from eth2spec.deneb import mainnet as deneb

from eth2spec.latest.constants_0 import *
from eth2spec.latest.funcs_0 import *
from eth2spec.latest.classes_0 import *
from eth2spec.latest.constants_1 import *
from eth2spec.latest.classes_1 import *
from eth2spec.latest.funcs_1 import *
from eth2spec.latest.funcs_2_write_state import *
from eth2spec.latest.funcs_2_read_store import *
from eth2spec.latest.funcs_2_read_state import *
from eth2spec.latest.funcs_3_1_block import *


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


def upgrade_to_bellatrix(pre: altair.BeaconState) -> BeaconState:
    epoch = altair.get_current_epoch(pre)
    post = BeaconState(
        genesis_time=pre.genesis_time,
        genesis_validators_root=pre.genesis_validators_root,
        slot=pre.slot,
        fork=Fork(
            previous_version=pre.fork.current_version,
            # [New in Bellatrix]
            current_version=config.BELLATRIX_FORK_VERSION,
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
        previous_epoch_participation=pre.previous_epoch_participation,
        current_epoch_participation=pre.current_epoch_participation,
        justification_bits=pre.justification_bits,
        previous_justified_checkpoint=pre.previous_justified_checkpoint,
        current_justified_checkpoint=pre.current_justified_checkpoint,
        finalized_checkpoint=pre.finalized_checkpoint,
        inactivity_scores=pre.inactivity_scores,
        current_sync_committee=pre.current_sync_committee,
        next_sync_committee=pre.next_sync_committee,
        # [New in Bellatrix]
        latest_execution_payload_header=ExecutionPayloadHeader(),
    )

    return post


def upgrade_to_capella(pre: bellatrix.BeaconState) -> BeaconState:
    epoch = bellatrix.get_current_epoch(pre)
    latest_execution_payload_header = ExecutionPayloadHeader(
        parent_hash=pre.latest_execution_payload_header.parent_hash,
        fee_recipient=pre.latest_execution_payload_header.fee_recipient,
        state_root=pre.latest_execution_payload_header.state_root,
        receipts_root=pre.latest_execution_payload_header.receipts_root,
        logs_bloom=pre.latest_execution_payload_header.logs_bloom,
        prev_randao=pre.latest_execution_payload_header.prev_randao,
        block_number=pre.latest_execution_payload_header.block_number,
        gas_limit=pre.latest_execution_payload_header.gas_limit,
        gas_used=pre.latest_execution_payload_header.gas_used,
        timestamp=pre.latest_execution_payload_header.timestamp,
        extra_data=pre.latest_execution_payload_header.extra_data,
        base_fee_per_gas=pre.latest_execution_payload_header.base_fee_per_gas,
        block_hash=pre.latest_execution_payload_header.block_hash,
        transactions_root=pre.latest_execution_payload_header.transactions_root,
        # [New in Capella]
        withdrawals_root=Root(),
    )
    post = BeaconState(
        genesis_time=pre.genesis_time,
        genesis_validators_root=pre.genesis_validators_root,
        slot=pre.slot,
        fork=Fork(
            previous_version=pre.fork.current_version,
            current_version=config.CAPELLA_FORK_VERSION,
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
        previous_epoch_participation=pre.previous_epoch_participation,
        current_epoch_participation=pre.current_epoch_participation,
        justification_bits=pre.justification_bits,
        previous_justified_checkpoint=pre.previous_justified_checkpoint,
        current_justified_checkpoint=pre.current_justified_checkpoint,
        finalized_checkpoint=pre.finalized_checkpoint,
        inactivity_scores=pre.inactivity_scores,
        current_sync_committee=pre.current_sync_committee,
        next_sync_committee=pre.next_sync_committee,
        latest_execution_payload_header=latest_execution_payload_header,
        # [New in Capella]
        next_withdrawal_index=WithdrawalIndex(0),
        # [New in Capella]
        next_withdrawal_validator_index=ValidatorIndex(0),
        # [New in Capella]
        historical_summaries=List[HistoricalSummary, HISTORICAL_ROOTS_LIMIT]([]),
    )

    return post


def upgrade_lc_header_to_capella(pre: bellatrix.LightClientHeader) -> LightClientHeader:
    return LightClientHeader(
        beacon=pre.beacon,
    )


def upgrade_lc_bootstrap_to_capella(
    pre: bellatrix.LightClientBootstrap,
) -> LightClientBootstrap:
    return LightClientBootstrap(
        header=upgrade_lc_header_to_capella(pre.header),
        current_sync_committee=pre.current_sync_committee,
        current_sync_committee_branch=pre.current_sync_committee_branch,
    )


def upgrade_lc_update_to_capella(pre: bellatrix.LightClientUpdate) -> LightClientUpdate:
    return LightClientUpdate(
        attested_header=upgrade_lc_header_to_capella(pre.attested_header),
        next_sync_committee=pre.next_sync_committee,
        next_sync_committee_branch=pre.next_sync_committee_branch,
        finalized_header=upgrade_lc_header_to_capella(pre.finalized_header),
        finality_branch=pre.finality_branch,
        sync_aggregate=pre.sync_aggregate,
        signature_slot=pre.signature_slot,
    )


def upgrade_lc_finality_update_to_capella(
    pre: bellatrix.LightClientFinalityUpdate,
) -> LightClientFinalityUpdate:
    return LightClientFinalityUpdate(
        attested_header=upgrade_lc_header_to_capella(pre.attested_header),
        finalized_header=upgrade_lc_header_to_capella(pre.finalized_header),
        finality_branch=pre.finality_branch,
        sync_aggregate=pre.sync_aggregate,
        signature_slot=pre.signature_slot,
    )


def upgrade_lc_optimistic_update_to_capella(
    pre: bellatrix.LightClientOptimisticUpdate,
) -> LightClientOptimisticUpdate:
    return LightClientOptimisticUpdate(
        attested_header=upgrade_lc_header_to_capella(pre.attested_header),
        sync_aggregate=pre.sync_aggregate,
        signature_slot=pre.signature_slot,
    )


def upgrade_lc_store_to_capella(pre: bellatrix.LightClientStore) -> LightClientStore:
    if pre.best_valid_update is None:
        best_valid_update = None
    else:
        best_valid_update = upgrade_lc_update_to_capella(pre.best_valid_update)
    return LightClientStore(
        finalized_header=upgrade_lc_header_to_capella(pre.finalized_header),
        current_sync_committee=pre.current_sync_committee,
        next_sync_committee=pre.next_sync_committee,
        best_valid_update=best_valid_update,
        optimistic_header=upgrade_lc_header_to_capella(pre.optimistic_header),
        previous_max_active_participants=pre.previous_max_active_participants,
        current_max_active_participants=pre.current_max_active_participants,
    )


def upgrade_to_deneb(pre: capella.BeaconState) -> BeaconState:
    epoch = capella.get_current_epoch(pre)
    latest_execution_payload_header = ExecutionPayloadHeader(
        parent_hash=pre.latest_execution_payload_header.parent_hash,
        fee_recipient=pre.latest_execution_payload_header.fee_recipient,
        state_root=pre.latest_execution_payload_header.state_root,
        receipts_root=pre.latest_execution_payload_header.receipts_root,
        logs_bloom=pre.latest_execution_payload_header.logs_bloom,
        prev_randao=pre.latest_execution_payload_header.prev_randao,
        block_number=pre.latest_execution_payload_header.block_number,
        gas_limit=pre.latest_execution_payload_header.gas_limit,
        gas_used=pre.latest_execution_payload_header.gas_used,
        timestamp=pre.latest_execution_payload_header.timestamp,
        extra_data=pre.latest_execution_payload_header.extra_data,
        base_fee_per_gas=pre.latest_execution_payload_header.base_fee_per_gas,
        block_hash=pre.latest_execution_payload_header.block_hash,
        transactions_root=pre.latest_execution_payload_header.transactions_root,
        withdrawals_root=pre.latest_execution_payload_header.withdrawals_root,
        # [New in Deneb:EIP4844]
        blob_gas_used=uint64(0),
        # [New in Deneb:EIP4844]
        excess_blob_gas=uint64(0),
    )
    post = BeaconState(
        genesis_time=pre.genesis_time,
        genesis_validators_root=pre.genesis_validators_root,
        slot=pre.slot,
        fork=Fork(
            previous_version=pre.fork.current_version,
            # [Modified in Deneb]
            current_version=config.DENEB_FORK_VERSION,
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
        previous_epoch_participation=pre.previous_epoch_participation,
        current_epoch_participation=pre.current_epoch_participation,
        justification_bits=pre.justification_bits,
        previous_justified_checkpoint=pre.previous_justified_checkpoint,
        current_justified_checkpoint=pre.current_justified_checkpoint,
        finalized_checkpoint=pre.finalized_checkpoint,
        inactivity_scores=pre.inactivity_scores,
        current_sync_committee=pre.current_sync_committee,
        next_sync_committee=pre.next_sync_committee,
        # [Modified in Deneb:EIP4844]
        latest_execution_payload_header=latest_execution_payload_header,
        next_withdrawal_index=pre.next_withdrawal_index,
        next_withdrawal_validator_index=pre.next_withdrawal_validator_index,
        historical_summaries=pre.historical_summaries,
    )

    return post


def upgrade_lc_header_to_deneb(pre: capella.LightClientHeader) -> LightClientHeader:
    return LightClientHeader(
        beacon=pre.beacon,
        execution=ExecutionPayloadHeader(
            parent_hash=pre.execution.parent_hash,
            fee_recipient=pre.execution.fee_recipient,
            state_root=pre.execution.state_root,
            receipts_root=pre.execution.receipts_root,
            logs_bloom=pre.execution.logs_bloom,
            prev_randao=pre.execution.prev_randao,
            block_number=pre.execution.block_number,
            gas_limit=pre.execution.gas_limit,
            gas_used=pre.execution.gas_used,
            timestamp=pre.execution.timestamp,
            extra_data=pre.execution.extra_data,
            base_fee_per_gas=pre.execution.base_fee_per_gas,
            block_hash=pre.execution.block_hash,
            transactions_root=pre.execution.transactions_root,
            withdrawals_root=pre.execution.withdrawals_root,
            blob_gas_used=uint64(0),  # [New in Deneb:EIP4844]
            excess_blob_gas=uint64(0),  # [New in Deneb:EIP4844]
        ),
        execution_branch=pre.execution_branch,
    )


def upgrade_lc_bootstrap_to_deneb(
    pre: capella.LightClientBootstrap,
) -> LightClientBootstrap:
    return LightClientBootstrap(
        header=upgrade_lc_header_to_deneb(pre.header),
        current_sync_committee=pre.current_sync_committee,
        current_sync_committee_branch=pre.current_sync_committee_branch,
    )


def upgrade_lc_update_to_deneb(pre: capella.LightClientUpdate) -> LightClientUpdate:
    return LightClientUpdate(
        attested_header=upgrade_lc_header_to_deneb(pre.attested_header),
        next_sync_committee=pre.next_sync_committee,
        next_sync_committee_branch=pre.next_sync_committee_branch,
        finalized_header=upgrade_lc_header_to_deneb(pre.finalized_header),
        finality_branch=pre.finality_branch,
        sync_aggregate=pre.sync_aggregate,
        signature_slot=pre.signature_slot,
    )


def upgrade_lc_finality_update_to_deneb(
    pre: capella.LightClientFinalityUpdate,
) -> LightClientFinalityUpdate:
    return LightClientFinalityUpdate(
        attested_header=upgrade_lc_header_to_deneb(pre.attested_header),
        finalized_header=upgrade_lc_header_to_deneb(pre.finalized_header),
        finality_branch=pre.finality_branch,
        sync_aggregate=pre.sync_aggregate,
        signature_slot=pre.signature_slot,
    )


def upgrade_lc_optimistic_update_to_deneb(
    pre: capella.LightClientOptimisticUpdate,
) -> LightClientOptimisticUpdate:
    return LightClientOptimisticUpdate(
        attested_header=upgrade_lc_header_to_deneb(pre.attested_header),
        sync_aggregate=pre.sync_aggregate,
        signature_slot=pre.signature_slot,
    )


def upgrade_lc_store_to_deneb(pre: capella.LightClientStore) -> LightClientStore:
    if pre.best_valid_update is None:
        best_valid_update = None
    else:
        best_valid_update = upgrade_lc_update_to_deneb(pre.best_valid_update)
    return LightClientStore(
        finalized_header=upgrade_lc_header_to_deneb(pre.finalized_header),
        current_sync_committee=pre.current_sync_committee,
        next_sync_committee=pre.next_sync_committee,
        best_valid_update=best_valid_update,
        optimistic_header=upgrade_lc_header_to_deneb(pre.optimistic_header),
        previous_max_active_participants=pre.previous_max_active_participants,
        current_max_active_participants=pre.current_max_active_participants,
    )


def upgrade_to_electra(pre: deneb.BeaconState) -> BeaconState:
    epoch = deneb.get_current_epoch(pre)

    earliest_exit_epoch = compute_activation_exit_epoch(get_current_epoch(pre))
    for validator in pre.validators:
        if validator.exit_epoch != FAR_FUTURE_EPOCH:
            if validator.exit_epoch > earliest_exit_epoch:
                earliest_exit_epoch = validator.exit_epoch
    earliest_exit_epoch += Epoch(1)

    post = BeaconState(
        genesis_time=pre.genesis_time,
        genesis_validators_root=pre.genesis_validators_root,
        slot=pre.slot,
        fork=Fork(
            previous_version=pre.fork.current_version,
            # [Modified in Electra]
            current_version=config.ELECTRA_FORK_VERSION,
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
        previous_epoch_participation=pre.previous_epoch_participation,
        current_epoch_participation=pre.current_epoch_participation,
        justification_bits=pre.justification_bits,
        previous_justified_checkpoint=pre.previous_justified_checkpoint,
        current_justified_checkpoint=pre.current_justified_checkpoint,
        finalized_checkpoint=pre.finalized_checkpoint,
        inactivity_scores=pre.inactivity_scores,
        current_sync_committee=pre.current_sync_committee,
        next_sync_committee=pre.next_sync_committee,
        latest_execution_payload_header=pre.latest_execution_payload_header,
        next_withdrawal_index=pre.next_withdrawal_index,
        next_withdrawal_validator_index=pre.next_withdrawal_validator_index,
        historical_summaries=pre.historical_summaries,
        # [New in Electra:EIP6110]
        deposit_requests_start_index=UNSET_DEPOSIT_REQUESTS_START_INDEX,
        # [New in Electra:EIP7251]
        deposit_balance_to_consume=0,
        # [New in Electra:EIP7251]
        exit_balance_to_consume=0,
        # [New in Electra:EIP7251]
        earliest_exit_epoch=earliest_exit_epoch,
        # [New in Electra:EIP7251]
        consolidation_balance_to_consume=0,
        # [New in Electra:EIP7251]
        earliest_consolidation_epoch=compute_activation_exit_epoch(
            get_current_epoch(pre)
        ),
        # [New in Electra:EIP7251]
        pending_deposits=[],
        # [New in Electra:EIP7251]
        pending_partial_withdrawals=[],
        # [New in Electra:EIP7251]
        pending_consolidations=[],
    )

    post.exit_balance_to_consume = get_activation_exit_churn_limit(post)
    post.consolidation_balance_to_consume = get_consolidation_churn_limit(post)

    # [New in Electra:EIP7251]
    # add validators that are not yet active to pending balance deposits
    pre_activation = sorted(
        [
            index
            for index, validator in enumerate(post.validators)
            if validator.activation_epoch == FAR_FUTURE_EPOCH
        ],
        key=lambda index: (post.validators[index].activation_eligibility_epoch, index),
    )

    for index in pre_activation:
        balance = post.balances[index]
        post.balances[index] = 0
        validator = post.validators[index]
        validator.effective_balance = 0
        validator.activation_eligibility_epoch = FAR_FUTURE_EPOCH
        # Use bls.G2_POINT_AT_INFINITY as a signature field placeholder
        # and GENESIS_SLOT to distinguish from a pending deposit request
        post.pending_deposits.append(
            PendingDeposit(
                pubkey=validator.pubkey,
                withdrawal_credentials=validator.withdrawal_credentials,
                amount=balance,
                signature=bls.G2_POINT_AT_INFINITY,
                slot=GENESIS_SLOT,
            )
        )

    # Ensure early adopters of compounding credentials go through the activation churn
    for index, validator in enumerate(post.validators):
        if has_compounding_withdrawal_credential(validator):
            queue_excess_active_balance(post, ValidatorIndex(index))

    return post

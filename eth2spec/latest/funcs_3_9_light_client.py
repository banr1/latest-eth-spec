# pyright: reportInvalidTypeForm=false

from eth2spec.latest.constants_0 import *
from eth2spec.latest.funcs_0 import *
from eth2spec.latest.classes_0 import *
from eth2spec.latest.constants_1 import *
from eth2spec.latest.classes_1 import *
from eth2spec.latest.funcs_1 import *
from eth2spec.latest.funcs_2 import *
from eth2spec.latest.funcs_2_read_state import *


GeneralizedIndex = int


def process_light_client_update(
    store: LightClientStore,
    update: LightClientUpdate,
    current_slot: Slot,
    genesis_validators_root: Root,
) -> None:
    validate_light_client_update(store, update, current_slot, genesis_validators_root)

    sync_committee_bits = update.sync_aggregate.sync_committee_bits

    # Update the best update in case we have to force-update to it if the timeout elapses
    if store.best_valid_update is None or is_better_update(
        update, store.best_valid_update
    ):
        store.best_valid_update = update

    # Track the maximum number of active participants in the committee signatures
    store.current_max_active_participants = max(
        store.current_max_active_participants,
        sum(sync_committee_bits),
    )

    # Update the optimistic header
    if (
        sum(sync_committee_bits) > get_safety_threshold(store)
        and update.attested_header.beacon.slot > store.optimistic_header.beacon.slot
    ):
        store.optimistic_header = update.attested_header

    # Update finalized header
    update_has_finalized_next_sync_committee = (
        not is_next_sync_committee_known(store)
        and is_sync_committee_update(update)
        and is_finality_update(update)
        and (
            compute_sync_committee_period_at_slot(update.finalized_header.beacon.slot)
            == compute_sync_committee_period_at_slot(update.attested_header.beacon.slot)
        )
    )
    if sum(sync_committee_bits) * 3 >= len(sync_committee_bits) * 2 and (
        update.finalized_header.beacon.slot > store.finalized_header.beacon.slot
        or update_has_finalized_next_sync_committee
    ):
        # Normal update through 2/3 threshold
        apply_light_client_update(store, update)
        store.best_valid_update = None


def validate_light_client_update(
    store: LightClientStore,
    update: LightClientUpdate,
    current_slot: Slot,
    genesis_validators_root: Root,
) -> None:
    # Verify sync committee has sufficient participants
    sync_aggregate = update.sync_aggregate
    assert sum(sync_aggregate.sync_committee_bits) >= MIN_SYNC_COMMITTEE_PARTICIPANTS

    # Verify update does not skip a sync committee period
    assert is_valid_light_client_header(update.attested_header)
    update_attested_slot = update.attested_header.beacon.slot
    update_finalized_slot = update.finalized_header.beacon.slot
    assert (
        current_slot
        >= update.signature_slot
        > update_attested_slot
        >= update_finalized_slot
    )
    store_period = compute_sync_committee_period_at_slot(
        store.finalized_header.beacon.slot
    )
    update_signature_period = compute_sync_committee_period_at_slot(
        update.signature_slot
    )
    if is_next_sync_committee_known(store):
        assert update_signature_period in (store_period, store_period + 1)
    else:
        assert update_signature_period == store_period

    # Verify update is relevant
    update_attested_period = compute_sync_committee_period_at_slot(update_attested_slot)
    update_has_next_sync_committee = not is_next_sync_committee_known(store) and (
        is_sync_committee_update(update) and update_attested_period == store_period
    )
    assert (
        update_attested_slot > store.finalized_header.beacon.slot
        or update_has_next_sync_committee
    )

    # Verify that the `finality_branch`, if present, confirms `finalized_header`
    # to match the finalized checkpoint root saved in the state of `attested_header`.
    # Note that the genesis finalized checkpoint root is represented as a zero hash.
    if not is_finality_update(update):
        assert update.finalized_header == LightClientHeader()
    else:
        if update_finalized_slot == GENESIS_SLOT:
            assert update.finalized_header == LightClientHeader()
            finalized_root = Bytes32()
        else:
            assert is_valid_light_client_header(update.finalized_header)
            finalized_root = hash_tree_root(update.finalized_header.beacon)
        assert is_valid_normalized_merkle_branch(
            leaf=finalized_root,
            branch=update.finality_branch,
            gindex=finalized_root_gindex_at_slot(update.attested_header.beacon.slot),
            root=update.attested_header.beacon.state_root,
        )

    # Verify that the `next_sync_committee`, if present, actually is the next sync committee saved in the
    # state of the `attested_header`
    if not is_sync_committee_update(update):
        assert update.next_sync_committee == SyncCommittee()
    else:
        if update_attested_period == store_period and is_next_sync_committee_known(
            store
        ):
            assert update.next_sync_committee == store.next_sync_committee
        assert is_valid_normalized_merkle_branch(
            leaf=hash_tree_root(update.next_sync_committee),
            branch=update.next_sync_committee_branch,
            gindex=next_sync_committee_gindex_at_slot(
                update.attested_header.beacon.slot
            ),
            root=update.attested_header.beacon.state_root,
        )

    # Verify sync committee aggregate signature
    if update_signature_period == store_period:
        sync_committee = store.current_sync_committee
    else:
        sync_committee = store.next_sync_committee
    participant_pubkeys = [
        pubkey
        for (bit, pubkey) in zip(
            sync_aggregate.sync_committee_bits, sync_committee.pubkeys
        )
        if bit
    ]
    fork_version_slot = max(update.signature_slot, Slot(1)) - Slot(1)
    fork_version = compute_fork_version(compute_epoch_at_slot(fork_version_slot))
    domain = compute_domain(
        DOMAIN_SYNC_COMMITTEE, fork_version, genesis_validators_root
    )
    signing_root = compute_signing_root(update.attested_header.beacon, domain)
    assert bls.FastAggregateVerify(
        participant_pubkeys, signing_root, sync_aggregate.sync_committee_signature
    )


def is_better_update(
    new_update: LightClientUpdate, old_update: LightClientUpdate
) -> bool:
    # Compare supermajority (> 2/3) sync committee participation
    max_active_participants = len(new_update.sync_aggregate.sync_committee_bits)
    new_num_active_participants = sum(new_update.sync_aggregate.sync_committee_bits)
    old_num_active_participants = sum(old_update.sync_aggregate.sync_committee_bits)
    new_has_supermajority = (
        new_num_active_participants * 3 >= max_active_participants * 2
    )
    old_has_supermajority = (
        old_num_active_participants * 3 >= max_active_participants * 2
    )
    if new_has_supermajority != old_has_supermajority:
        return new_has_supermajority
    if (
        not new_has_supermajority
        and new_num_active_participants != old_num_active_participants
    ):
        return new_num_active_participants > old_num_active_participants

    # Compare presence of relevant sync committee
    new_has_relevant_sync_committee = is_sync_committee_update(new_update) and (
        compute_sync_committee_period_at_slot(new_update.attested_header.beacon.slot)
        == compute_sync_committee_period_at_slot(new_update.signature_slot)
    )
    old_has_relevant_sync_committee = is_sync_committee_update(old_update) and (
        compute_sync_committee_period_at_slot(old_update.attested_header.beacon.slot)
        == compute_sync_committee_period_at_slot(old_update.signature_slot)
    )
    if new_has_relevant_sync_committee != old_has_relevant_sync_committee:
        return new_has_relevant_sync_committee

    # Compare indication of any finality
    new_has_finality = is_finality_update(new_update)
    old_has_finality = is_finality_update(old_update)
    if new_has_finality != old_has_finality:
        return new_has_finality

    # Compare sync committee finality
    if new_has_finality:
        new_has_sync_committee_finality = compute_sync_committee_period_at_slot(
            new_update.finalized_header.beacon.slot
        ) == compute_sync_committee_period_at_slot(
            new_update.attested_header.beacon.slot
        )
        old_has_sync_committee_finality = compute_sync_committee_period_at_slot(
            old_update.finalized_header.beacon.slot
        ) == compute_sync_committee_period_at_slot(
            old_update.attested_header.beacon.slot
        )
        if new_has_sync_committee_finality != old_has_sync_committee_finality:
            return new_has_sync_committee_finality

    # Tiebreaker 1: Sync committee participation beyond supermajority
    if new_num_active_participants != old_num_active_participants:
        return new_num_active_participants > old_num_active_participants

    # Tiebreaker 2: Prefer older data (fewer changes to best)
    if new_update.attested_header.beacon.slot != old_update.attested_header.beacon.slot:
        return (
            new_update.attested_header.beacon.slot
            < old_update.attested_header.beacon.slot
        )

    # Tiebreaker 3: Prefer updates with earlier signature slots
    return new_update.signature_slot < old_update.signature_slot


def get_safety_threshold(store: LightClientStore) -> uint64:
    return (
        max(
            store.previous_max_active_participants,
            store.current_max_active_participants,
        )
        // 2
    )


def apply_light_client_update(
    store: LightClientStore, update: LightClientUpdate
) -> None:
    store_period = compute_sync_committee_period_at_slot(
        store.finalized_header.beacon.slot
    )
    update_finalized_period = compute_sync_committee_period_at_slot(
        update.finalized_header.beacon.slot
    )
    if not is_next_sync_committee_known(store):
        assert update_finalized_period == store_period
        store.next_sync_committee = update.next_sync_committee
    elif update_finalized_period == store_period + 1:
        store.current_sync_committee = store.next_sync_committee
        store.next_sync_committee = update.next_sync_committee
        store.previous_max_active_participants = store.current_max_active_participants
        store.current_max_active_participants = 0
    if update.finalized_header.beacon.slot > store.finalized_header.beacon.slot:
        store.finalized_header = update.finalized_header
        if store.finalized_header.beacon.slot > store.optimistic_header.beacon.slot:
            store.optimistic_header = store.finalized_header


def is_next_sync_committee_known(store: LightClientStore) -> bool:
    return store.next_sync_committee != SyncCommittee()


def finalized_root_gindex_at_slot(slot: Slot) -> GeneralizedIndex:
    epoch = compute_epoch_at_slot(slot)

    # [Modified in Electra]
    if epoch >= config.ELECTRA_FORK_EPOCH:
        return FINALIZED_ROOT_GINDEX_ELECTRA
    return FINALIZED_ROOT_GINDEX


def is_sync_committee_update(update: LightClientUpdate) -> bool:
    return update.next_sync_committee_branch != NextSyncCommitteeBranch()


def is_finality_update(update: LightClientUpdate) -> bool:
    return update.finality_branch != FinalityBranch()


def next_sync_committee_gindex_at_slot(slot: Slot) -> GeneralizedIndex:
    epoch = compute_epoch_at_slot(slot)

    # [Modified in Electra]
    if epoch >= config.ELECTRA_FORK_EPOCH:
        return NEXT_SYNC_COMMITTEE_GINDEX_ELECTRA
    return NEXT_SYNC_COMMITTEE_GINDEX


def compute_fork_version(epoch: Epoch) -> Version:
    """
    Return the fork version at the given ``epoch``.
    """
    if epoch >= config.ELECTRA_FORK_EPOCH:
        return config.ELECTRA_FORK_VERSION
    if epoch >= config.DENEB_FORK_EPOCH:
        return config.DENEB_FORK_VERSION
    if epoch >= config.CAPELLA_FORK_EPOCH:
        return config.CAPELLA_FORK_VERSION
    if epoch >= config.BELLATRIX_FORK_EPOCH:
        return config.BELLATRIX_FORK_VERSION
    if epoch >= config.ALTAIR_FORK_EPOCH:
        return config.ALTAIR_FORK_VERSION
    return config.GENESIS_FORK_VERSION


def compute_sync_committee_period_at_slot(slot: Slot) -> uint64:
    return compute_sync_committee_period(compute_epoch_at_slot(slot))


def block_to_light_client_header(block: SignedBeaconBlock) -> LightClientHeader:
    epoch = compute_epoch_at_slot(block.message.slot)

    if epoch >= config.CAPELLA_FORK_EPOCH:
        payload = block.message.body.execution_payload
        execution_header = ExecutionPayloadHeader(
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
        )

        # [New in Deneb:EIP4844]
        if epoch >= config.DENEB_FORK_EPOCH:
            execution_header.blob_gas_used = payload.blob_gas_used
            execution_header.excess_blob_gas = payload.excess_blob_gas

        execution_branch = ExecutionBranch(
            compute_merkle_proof(block.message.body, EXECUTION_PAYLOAD_GINDEX)
        )
    else:
        # Note that during fork transitions, `finalized_header` may still point to earlier forks.
        # While Bellatrix blocks also contain an `ExecutionPayload` (minus `withdrawals_root`),
        # it was not included in the corresponding light client data. To ensure compatibility
        # with legacy data going through `upgrade_lc_header_to_capella`, leave out execution data.
        execution_header = ExecutionPayloadHeader()
        execution_branch = ExecutionBranch()

    return LightClientHeader(
        beacon=BeaconBlockHeader(
            slot=block.message.slot,
            proposer_index=block.message.proposer_index,
            parent_root=block.message.parent_root,
            state_root=block.message.state_root,
            body_root=hash_tree_root(block.message.body),
        ),
        execution=execution_header,
        execution_branch=execution_branch,
    )

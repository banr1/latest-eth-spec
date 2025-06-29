# pyright: reportInvalidTypeForm=false

from lru import LRU
from dataclasses import (
    dataclass,
    field,
)
from typing import (
    Any,
    Callable,
    Dict,
    Set,
    Sequence,
    Tuple,
    Optional,
    TypeVar,
    NamedTuple,
    Final,
    Union as PyUnion,
    Protocol,
)

from eth2spec.utils.ssz.ssz_impl import hash_tree_root, copy, uint_to_bytes, ssz_serialize, ssz_deserialize
from eth2spec.utils.ssz.ssz_typing import (
    View,
    boolean,
    Container,
    List,
    Vector,
    uint8,
    uint32,
    uint64,
    uint256,
    Bytes1,
    Bytes4,
    Bytes8,
    Bytes20,
    Bytes32,
    Bytes48,
    Bytes96,
    Bitlist,
    Bitvector,
    ByteList,
    ByteVector,
    Path,
)
from eth2spec.utils import bls
from eth2spec.utils.hash_function import hash
from eth2spec.test.helpers.merkle import build_proof

from eth2spec.phase0 import mainnet as phase0
from eth2spec.altair import mainnet as altair
from eth2spec.bellatrix import mainnet as bellatrix
from eth2spec.capella import mainnet as capella
from eth2spec.deneb import mainnet as deneb

from eth2spec.latest_2.constants import *
from eth2spec.latest_2.classes import *
from eth2spec.latest_2.hyper_read_funcs import *
# from eth2spec.latest_2.write_state_funcs import *


SSZObject = TypeVar("SSZObject", bound=View)


SSZVariableName = str
GeneralizedIndex = int


T = TypeVar("T")  # For generic function
TPoint = TypeVar("TPoint")  # For generic function. G1 or G2 point.


fork = "electra"


def saturating_sub(a: int, b: int) -> int:
    """
    Computes a - b, saturating at numeric bounds.
    """
    return a - b if a > b else 0


def compute_fork_digest(
    current_version: Version, genesis_validators_root: Root
) -> ForkDigest:
    """
    Return the 4-byte fork digest for the ``current_version`` and ``genesis_validators_root``.
    This is a digest primarily used for domain separation on the p2p layer.
    4-bytes suffices for practical separation of forks/chains.
    """
    return ForkDigest(
        compute_fork_data_root(current_version, genesis_validators_root)[:4]
    )


def get_validator_churn_limit(state: BeaconState) -> uint64:
    """
    Return the validator churn limit for the current epoch.
    """
    active_validator_indices = get_active_validator_indices(
        state, get_current_epoch(state)
    )
    return max(
        config.MIN_PER_EPOCH_CHURN_LIMIT,
        uint64(len(active_validator_indices)) // config.CHURN_LIMIT_QUOTIENT,
    )


def is_valid_genesis_state(state: BeaconState) -> bool:
    if state.genesis_time < config.MIN_GENESIS_TIME:
        return False
    if (
        len(get_active_validator_indices(state, GENESIS_EPOCH))
        < config.MIN_GENESIS_ACTIVE_VALIDATOR_COUNT
    ):
        return False
    return True


def get_matching_source_attestations(
    state: BeaconState, epoch: Epoch
) -> Sequence[PendingAttestation]:
    assert epoch in (get_previous_epoch(state), get_current_epoch(state))
    return (
        state.current_epoch_attestations
        if epoch == get_current_epoch(state)
        else state.previous_epoch_attestations
    )


def get_matching_target_attestations(
    state: BeaconState, epoch: Epoch
) -> Sequence[PendingAttestation]:
    return [
        a
        for a in get_matching_source_attestations(state, epoch)
        if a.data.target.root == get_block_root(state, epoch)
    ]


def get_matching_head_attestations(
    state: BeaconState, epoch: Epoch
) -> Sequence[PendingAttestation]:
    return [
        a
        for a in get_matching_target_attestations(state, epoch)
        if a.data.beacon_block_root == get_block_root_at_slot(state, a.data.slot)
    ]


def get_unslashed_attesting_indices(
    state: BeaconState, attestations: Sequence[PendingAttestation]
) -> Set[ValidatorIndex]:
    output: Set[ValidatorIndex] = set()
    for a in attestations:
        output = output.union(get_attesting_indices(state, a))
    return set(filter(lambda index: not state.validators[index].slashed, output))


def get_attesting_balance(
    state: BeaconState, attestations: Sequence[PendingAttestation]
) -> Gwei:
    """
    Return the combined effective balance of the set of unslashed validators participating in ``attestations``.
    Note: ``get_total_balance`` returns ``EFFECTIVE_BALANCE_INCREMENT`` Gwei minimum to avoid divisions by zero.
    """
    return get_total_balance(
        state, get_unslashed_attesting_indices(state, attestations)
    )


def get_proposer_reward(state: BeaconState, attesting_index: ValidatorIndex) -> Gwei:
    return Gwei(get_base_reward(state, attesting_index) // PROPOSER_REWARD_QUOTIENT)


def get_attestation_component_deltas(
    state: BeaconState, attestations: Sequence[PendingAttestation]
) -> Tuple[Sequence[Gwei], Sequence[Gwei]]:
    """
    Helper with shared logic for use by get source, target, and head deltas functions
    """
    rewards = [Gwei(0)] * len(state.validators)
    penalties = [Gwei(0)] * len(state.validators)
    total_balance = get_total_active_balance(state)
    unslashed_attesting_indices = get_unslashed_attesting_indices(state, attestations)
    attesting_balance = get_total_balance(state, unslashed_attesting_indices)
    for index in get_eligible_validator_indices(state):
        if index in unslashed_attesting_indices:
            increment = EFFECTIVE_BALANCE_INCREMENT  # Factored out from balance totals to avoid uint64 overflow
            if is_in_inactivity_leak(state):
                # Since full base reward will be canceled out by inactivity penalty deltas,
                # optimal participation receives full base reward compensation here.
                rewards[index] += get_base_reward(state, index)
            else:
                reward_numerator = get_base_reward(state, index) * (
                    attesting_balance // increment
                )
                rewards[index] += reward_numerator // (total_balance // increment)
        else:
            penalties[index] += get_base_reward(state, index)
    return rewards, penalties


def get_source_deltas(state: BeaconState) -> Tuple[Sequence[Gwei], Sequence[Gwei]]:
    """
    Return attester micro-rewards/penalties for source-vote for each validator.
    """
    matching_source_attestations = get_matching_source_attestations(
        state, get_previous_epoch(state)
    )
    return get_attestation_component_deltas(state, matching_source_attestations)


def get_target_deltas(state: BeaconState) -> Tuple[Sequence[Gwei], Sequence[Gwei]]:
    """
    Return attester micro-rewards/penalties for target-vote for each validator.
    """
    matching_target_attestations = get_matching_target_attestations(
        state, get_previous_epoch(state)
    )
    return get_attestation_component_deltas(state, matching_target_attestations)


def get_head_deltas(state: BeaconState) -> Tuple[Sequence[Gwei], Sequence[Gwei]]:
    """
    Return attester micro-rewards/penalties for head-vote for each validator.
    """
    matching_head_attestations = get_matching_head_attestations(
        state, get_previous_epoch(state)
    )
    return get_attestation_component_deltas(state, matching_head_attestations)


def get_inclusion_delay_deltas(
    state: BeaconState,
) -> Tuple[Sequence[Gwei], Sequence[Gwei]]:
    """
    Return proposer and inclusion delay micro-rewards/penalties for each validator.
    """
    rewards = [Gwei(0) for _ in range(len(state.validators))]
    matching_source_attestations = get_matching_source_attestations(
        state, get_previous_epoch(state)
    )
    for index in get_unslashed_attesting_indices(state, matching_source_attestations):
        attestation = min(
            [
                a
                for a in matching_source_attestations
                if index in get_attesting_indices(state, a)
            ],
            key=lambda a: a.inclusion_delay,
        )
        rewards[attestation.proposer_index] += get_proposer_reward(state, index)
        max_attester_reward = Gwei(
            get_base_reward(state, index) - get_proposer_reward(state, index)
        )
        rewards[index] += Gwei(max_attester_reward // attestation.inclusion_delay)

    # No penalties associated with inclusion delay
    penalties = [Gwei(0) for _ in range(len(state.validators))]
    return rewards, penalties


def get_attestation_deltas(state: BeaconState) -> Tuple[Sequence[Gwei], Sequence[Gwei]]:
    """
    Return attestation reward/penalty deltas for each validator.
    """
    source_rewards, source_penalties = get_source_deltas(state)
    target_rewards, target_penalties = get_target_deltas(state)
    head_rewards, head_penalties = get_head_deltas(state)
    inclusion_delay_rewards, _ = get_inclusion_delay_deltas(state)
    _, inactivity_penalties = get_inactivity_penalty_deltas(state)

    rewards = [
        source_rewards[i]
        + target_rewards[i]
        + head_rewards[i]
        + inclusion_delay_rewards[i]
        for i in range(len(state.validators))
    ]

    penalties = [
        source_penalties[i]
        + target_penalties[i]
        + head_penalties[i]
        + inactivity_penalties[i]
        for i in range(len(state.validators))
    ]

    return rewards, penalties


def get_forkchoice_store(anchor_state: BeaconState, anchor_block: BeaconBlock) -> Store:
    assert anchor_block.state_root == hash_tree_root(anchor_state)
    anchor_root = hash_tree_root(anchor_block)
    anchor_epoch = get_current_epoch(anchor_state)
    justified_checkpoint = Checkpoint(epoch=anchor_epoch, root=anchor_root)
    finalized_checkpoint = Checkpoint(epoch=anchor_epoch, root=anchor_root)
    proposer_boost_root = Root()
    return Store(
        time=uint64(
            anchor_state.genesis_time + config.SECONDS_PER_SLOT * anchor_state.slot
        ),
        genesis_time=anchor_state.genesis_time,
        justified_checkpoint=justified_checkpoint,
        finalized_checkpoint=finalized_checkpoint,
        unrealized_justified_checkpoint=justified_checkpoint,
        unrealized_finalized_checkpoint=finalized_checkpoint,
        proposer_boost_root=proposer_boost_root,
        equivocating_indices=set(),
        blocks={anchor_root: copy(anchor_block)},
        block_states={anchor_root: copy(anchor_state)},
        checkpoint_states={justified_checkpoint: copy(anchor_state)},
        unrealized_justifications={anchor_root: justified_checkpoint},
    )


def calculate_committee_fraction(state: BeaconState, committee_percent: uint64) -> Gwei:
    committee_weight = get_total_active_balance(state) // SLOTS_PER_EPOCH
    return Gwei((committee_weight * committee_percent) // 100)


def get_proposer_score(store: Store) -> Gwei:
    justified_checkpoint_state = store.checkpoint_states[store.justified_checkpoint]
    committee_weight = (
        get_total_active_balance(justified_checkpoint_state) // SLOTS_PER_EPOCH
    )
    return (committee_weight * config.PROPOSER_SCORE_BOOST) // 100


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


def get_voting_source(store: Store, block_root: Root) -> Checkpoint:
    """
    Compute the voting source checkpoint in event that block with root ``block_root`` is the head block
    """
    block = store.blocks[block_root]
    current_epoch = get_current_store_epoch(store)
    block_epoch = compute_epoch_at_slot(block.slot)
    if current_epoch > block_epoch:
        # The block is from a prior epoch, the voting source will be pulled-up
        return store.unrealized_justifications[block_root]
    else:
        # The block is not from a prior epoch, therefore the voting source is not pulled up
        head_state = store.block_states[block_root]
        return head_state.current_justified_checkpoint


def filter_block_tree(
    store: Store, block_root: Root, blocks: Dict[Root, BeaconBlock]
) -> bool:
    block = store.blocks[block_root]
    children = [
        root
        for root in store.blocks.keys()
        if store.blocks[root].parent_root == block_root
    ]

    # If any children branches contain expected finalized/justified checkpoints,
    # add to filtered block-tree and signal viability to parent.
    if any(children):
        filter_block_tree_result = [
            filter_block_tree(store, child, blocks) for child in children
        ]
        if any(filter_block_tree_result):
            blocks[block_root] = block
            return True
        return False

    current_epoch = get_current_store_epoch(store)
    voting_source = get_voting_source(store, block_root)

    # The voting source should be either at the same height as the store's justified checkpoint or
    # not more than two epochs ago
    correct_justified = (
        store.justified_checkpoint.epoch == GENESIS_EPOCH
        or voting_source.epoch == store.justified_checkpoint.epoch
        or voting_source.epoch + 2 >= current_epoch
    )

    finalized_checkpoint_block = get_checkpoint_block(
        store,
        block_root,
        store.finalized_checkpoint.epoch,
    )

    correct_finalized = (
        store.finalized_checkpoint.epoch == GENESIS_EPOCH
        or store.finalized_checkpoint.root == finalized_checkpoint_block
    )

    # If expected finalized/justified, add to viable block-tree and signal viability to parent.
    if correct_justified and correct_finalized:
        blocks[block_root] = block
        return True

    # Otherwise, branch not viable
    return False


def get_filtered_block_tree(store: Store) -> Dict[Root, BeaconBlock]:
    """
    Retrieve a filtered block tree from ``store``, only returning branches
    whose leaf state's justified/finalized info agrees with that in ``store``.
    """
    base = store.justified_checkpoint.root
    blocks: Dict[Root, BeaconBlock] = {}
    filter_block_tree(store, base, blocks)
    return blocks


def get_head(store: Store) -> Root:
    # Get filtered block tree that only includes viable branches
    blocks = get_filtered_block_tree(store)
    # Execute the LMD-GHOST fork choice
    head = store.justified_checkpoint.root
    while True:
        children = [root for root in blocks.keys() if blocks[root].parent_root == head]
        if len(children) == 0:
            return head
        # Sort by latest attesting balance with ties broken lexicographically
        # Ties broken by favoring block with lexicographically higher root
        head = max(children, key=lambda root: (get_weight(store, root), root))


def is_head_late(store: Store, head_root: Root) -> bool:
    return not store.block_timeliness[head_root]


def is_shuffling_stable(slot: Slot) -> bool:
    return slot % SLOTS_PER_EPOCH != 0


def is_ffg_competitive(store: Store, head_root: Root, parent_root: Root) -> bool:
    return (
        store.unrealized_justifications[head_root]
        == store.unrealized_justifications[parent_root]
    )


def is_finalization_ok(store: Store, slot: Slot) -> bool:
    epochs_since_finalization = (
        compute_epoch_at_slot(slot) - store.finalized_checkpoint.epoch
    )
    return epochs_since_finalization <= config.REORG_MAX_EPOCHS_SINCE_FINALIZATION


def is_proposing_on_time(store: Store) -> bool:
    # Use half `config.SECONDS_PER_SLOT // INTERVALS_PER_SLOT` as the proposer reorg deadline
    time_into_slot = (store.time - store.genesis_time) % config.SECONDS_PER_SLOT
    proposer_reorg_cutoff = config.SECONDS_PER_SLOT // INTERVALS_PER_SLOT // 2
    return time_into_slot <= proposer_reorg_cutoff


def is_head_weak(store: Store, head_root: Root) -> bool:
    justified_state = store.checkpoint_states[store.justified_checkpoint]
    reorg_threshold = calculate_committee_fraction(
        justified_state, config.REORG_HEAD_WEIGHT_THRESHOLD
    )
    head_weight = get_weight(store, head_root)
    return head_weight < reorg_threshold


def is_parent_strong(store: Store, parent_root: Root) -> bool:
    justified_state = store.checkpoint_states[store.justified_checkpoint]
    parent_threshold = calculate_committee_fraction(
        justified_state, config.REORG_PARENT_WEIGHT_THRESHOLD
    )
    parent_weight = get_weight(store, parent_root)
    return parent_weight > parent_threshold


def get_proposer_head(store: Store, head_root: Root, slot: Slot) -> Root:
    head_block = store.blocks[head_root]
    parent_root = head_block.parent_root
    parent_block = store.blocks[parent_root]

    # Only re-org the head block if it arrived later than the attestation deadline.
    head_late = is_head_late(store, head_root)

    # Do not re-org on an epoch boundary where the proposer shuffling could change.
    shuffling_stable = is_shuffling_stable(slot)

    # Ensure that the FFG information of the new head will be competitive with the current head.
    ffg_competitive = is_ffg_competitive(store, head_root, parent_root)

    # Do not re-org if the chain is not finalizing with acceptable frequency.
    finalization_ok = is_finalization_ok(store, slot)

    # Only re-org if we are proposing on-time.
    proposing_on_time = is_proposing_on_time(store)

    # Only re-org a single slot at most.
    parent_slot_ok = parent_block.slot + 1 == head_block.slot
    current_time_ok = head_block.slot + 1 == slot
    single_slot_reorg = parent_slot_ok and current_time_ok

    # Check that the head has few enough votes to be overpowered by our proposer boost.
    assert store.proposer_boost_root != head_root  # ensure boost has worn off
    head_weak = is_head_weak(store, head_root)

    # Check that the missing votes are assigned to the parent and not being hoarded.
    parent_strong = is_parent_strong(store, parent_root)

    if all(
        [
            head_late,
            shuffling_stable,
            ffg_competitive,
            finalization_ok,
            proposing_on_time,
            single_slot_reorg,
            head_weak,
            parent_strong,
        ]
    ):
        # We can re-org the current head by building upon its parent block.
        return parent_root
    else:
        return head_root


def on_attester_slashing(store: Store, attester_slashing: AttesterSlashing) -> None:
    """
    Run ``on_attester_slashing`` immediately upon receiving a new ``AttesterSlashing``
    from either within a block or directly on the wire.
    """
    attestation_1 = attester_slashing.attestation_1
    attestation_2 = attester_slashing.attestation_2
    assert is_slashable_attestation_data(attestation_1.data, attestation_2.data)
    state = store.block_states[store.justified_checkpoint.root]
    assert is_valid_indexed_attestation(state, attestation_1)
    assert is_valid_indexed_attestation(state, attestation_2)

    indices = set(attestation_1.attesting_indices).intersection(
        attestation_2.attesting_indices
    )
    for index in indices:
        store.equivocating_indices.add(index)


def max_compressed_len(n: uint64) -> uint64:
    # Worst-case compressed length for a given payload of size n when using snappy:
    # https://github.com/google/snappy/blob/32ded457c0b1fe78ceb8397632c416568d6714a0/snappy.cc#L218C1-L218C47
    return uint64(32 + n + n / 6)


def max_message_size() -> uint64:
    # Allow 1024 bytes for framing and encoding overhead but at least 1MiB in case config.MAX_PAYLOAD_SIZE is small.
    return max(max_compressed_len(config.MAX_PAYLOAD_SIZE) + 1024, 1024 * 1024)


def compute_subscribed_subnet(node_id: NodeID, epoch: Epoch, index: int) -> SubnetID:
    node_id_prefix = node_id >> (NODE_ID_BITS - config.ATTESTATION_SUBNET_PREFIX_BITS)
    node_offset = node_id % config.EPOCHS_PER_SUBNET_SUBSCRIPTION
    permutation_seed = hash(
        uint_to_bytes(
            uint64((epoch + node_offset) // config.EPOCHS_PER_SUBNET_SUBSCRIPTION)
        )
    )
    permutated_prefix = compute_shuffled_index(
        node_id_prefix,
        1 << config.ATTESTATION_SUBNET_PREFIX_BITS,
        permutation_seed,
    )
    return SubnetID((permutated_prefix + index) % config.ATTESTATION_SUBNET_COUNT)


def compute_subscribed_subnets(node_id: NodeID, epoch: Epoch) -> Sequence[SubnetID]:
    return [
        compute_subscribed_subnet(node_id, epoch, index)
        for index in range(config.SUBNETS_PER_NODE)
    ]


def check_if_validator_active(
    state: BeaconState, validator_index: ValidatorIndex
) -> bool:
    validator = state.validators[validator_index]
    return is_active_validator(validator, get_current_epoch(state))


def get_committee_assignment(
    state: BeaconState, epoch: Epoch, validator_index: ValidatorIndex
) -> Optional[Tuple[Sequence[ValidatorIndex], CommitteeIndex, Slot]]:
    """
    Return the committee assignment in the ``epoch`` for ``validator_index``.
    ``assignment`` returned is a tuple of the following form:
        * ``assignment[0]`` is the list of validators in the committee
        * ``assignment[1]`` is the index to which the committee is assigned
        * ``assignment[2]`` is the slot at which the committee is assigned
    Return None if no assignment.
    """
    next_epoch = Epoch(get_current_epoch(state) + 1)
    assert epoch <= next_epoch

    start_slot = compute_start_slot_at_epoch(epoch)
    committee_count_per_slot = get_committee_count_per_slot(state, epoch)
    for slot in range(start_slot, start_slot + SLOTS_PER_EPOCH):
        for index in range(committee_count_per_slot):
            committee = get_beacon_committee(state, Slot(slot), CommitteeIndex(index))
            if validator_index in committee:
                return committee, CommitteeIndex(index), Slot(slot)
    return None


def is_proposer(state: BeaconState, validator_index: ValidatorIndex) -> bool:
    return get_beacon_proposer_index(state) == validator_index


def get_epoch_signature(
    state: BeaconState, block: BeaconBlock, privkey: int
) -> BLSSignature:
    domain = get_domain(state, DOMAIN_RANDAO, compute_epoch_at_slot(block.slot))
    signing_root = compute_signing_root(compute_epoch_at_slot(block.slot), domain)
    return bls.Sign(privkey, signing_root)


def compute_time_at_slot(state: BeaconState, slot: Slot) -> uint64:
    return uint64(state.genesis_time + slot * config.SECONDS_PER_SLOT)


def voting_period_start_time(state: BeaconState) -> uint64:
    eth1_voting_period_start_slot = Slot(
        state.slot - state.slot % (EPOCHS_PER_ETH1_VOTING_PERIOD * SLOTS_PER_EPOCH)
    )
    return compute_time_at_slot(state, eth1_voting_period_start_slot)


def is_candidate_block(block: Eth1Block, period_start: uint64) -> bool:
    return (
        block.timestamp + config.SECONDS_PER_ETH1_BLOCK * config.ETH1_FOLLOW_DISTANCE
        <= period_start
        and block.timestamp
        + config.SECONDS_PER_ETH1_BLOCK * config.ETH1_FOLLOW_DISTANCE * 2
        >= period_start
    )


def get_eth1_vote(state: BeaconState, eth1_chain: Sequence[Eth1Block]) -> Eth1Data:
    # [New in Electra:EIP6110]
    if state.eth1_deposit_index == state.deposit_requests_start_index:
        return state.eth1_data

    period_start = voting_period_start_time(state)
    # `eth1_chain` abstractly represents all blocks in the eth1 chain sorted by ascending block height
    votes_to_consider = [
        get_eth1_data(block)
        for block in eth1_chain
        if (
            is_candidate_block(block, period_start)
            # Ensure cannot move back to earlier deposit contract states
            and get_eth1_data(block).deposit_count >= state.eth1_data.deposit_count
        )
    ]

    # Valid votes already cast during this period
    valid_votes = [vote for vote in state.eth1_data_votes if vote in votes_to_consider]

    # Default vote on latest eth1 block data in the period range unless eth1 chain is not live
    # Non-substantive casting for linter
    state_eth1_data: Eth1Data = state.eth1_data
    default_vote = (
        votes_to_consider[len(votes_to_consider) - 1]
        if any(votes_to_consider)
        else state_eth1_data
    )

    return max(
        valid_votes,
        # Tiebreak by smallest distance
        key=lambda v: (
            valid_votes.count(v),
            -valid_votes.index(v),
        ),
        default=default_vote,
    )


def get_block_signature(
    state: BeaconState, block: BeaconBlock, privkey: int
) -> BLSSignature:
    domain = get_domain(
        state, DOMAIN_BEACON_PROPOSER, compute_epoch_at_slot(block.slot)
    )
    signing_root = compute_signing_root(block, domain)
    return bls.Sign(privkey, signing_root)


def get_attestation_signature(
    state: BeaconState, attestation_data: AttestationData, privkey: int
) -> BLSSignature:
    domain = get_domain(state, DOMAIN_BEACON_ATTESTER, attestation_data.target.epoch)
    signing_root = compute_signing_root(attestation_data, domain)
    return bls.Sign(privkey, signing_root)


def compute_subnet_for_attestation(
    committees_per_slot: uint64, slot: Slot, committee_index: CommitteeIndex
) -> SubnetID:
    """
    Compute the correct subnet for an attestation for Phase 0.
    Note, this mimics expected future behavior where attestations will be mapped to their shard subnet.
    """
    slots_since_epoch_start = uint64(slot % SLOTS_PER_EPOCH)
    committees_since_epoch_start = committees_per_slot * slots_since_epoch_start

    return SubnetID(
        (committees_since_epoch_start + committee_index)
        % config.ATTESTATION_SUBNET_COUNT
    )


def get_slot_signature(state: BeaconState, slot: Slot, privkey: int) -> BLSSignature:
    domain = get_domain(state, DOMAIN_SELECTION_PROOF, compute_epoch_at_slot(slot))
    signing_root = compute_signing_root(slot, domain)
    return bls.Sign(privkey, signing_root)


def is_aggregator(
    state: BeaconState, slot: Slot, index: CommitteeIndex, slot_signature: BLSSignature
) -> bool:
    committee = get_beacon_committee(state, slot, index)
    modulo = max(1, len(committee) // TARGET_AGGREGATORS_PER_COMMITTEE)
    return bytes_to_uint64(hash(slot_signature)[0:8]) % modulo == 0


def get_aggregate_signature(attestations: Sequence[Attestation]) -> BLSSignature:
    signatures = [attestation.signature for attestation in attestations]
    return bls.Aggregate(signatures)


def get_aggregate_and_proof(
    state: BeaconState,
    aggregator_index: ValidatorIndex,
    aggregate: Attestation,
    privkey: int,
) -> AggregateAndProof:
    return AggregateAndProof(
        aggregator_index=aggregator_index,
        aggregate=aggregate,
        selection_proof=get_slot_signature(state, aggregate.data.slot, privkey),
    )


def get_aggregate_and_proof_signature(
    state: BeaconState, aggregate_and_proof: AggregateAndProof, privkey: int
) -> BLSSignature:
    aggregate = aggregate_and_proof.aggregate
    domain = get_domain(
        state, DOMAIN_AGGREGATE_AND_PROOF, compute_epoch_at_slot(aggregate.data.slot)
    )
    signing_root = compute_signing_root(aggregate_and_proof, domain)
    return bls.Sign(privkey, signing_root)


def compute_weak_subjectivity_period(state: BeaconState) -> uint64:
    """
    Returns the weak subjectivity period for the current ``state``.
    This computation takes into account the effect of:
        - validator set churn (bounded by ``get_balance_churn_limit()`` per epoch)
    A detailed calculation can be found at:
    https://notes.ethereum.org/@CarlBeek/electra_weak_subjectivity
    """
    t = get_total_active_balance(state)
    delta = get_balance_churn_limit(state)
    epochs_for_validator_set_churn = SAFETY_DECAY * t // (2 * delta * 100)
    return config.MIN_VALIDATOR_WITHDRAWABILITY_DELAY + epochs_for_validator_set_churn


def is_within_weak_subjectivity_period(
    store: Store, ws_state: BeaconState, ws_checkpoint: Checkpoint
) -> bool:
    # Clients may choose to validate the input state against the input Weak Subjectivity Checkpoint
    assert ws_state.latest_block_header.state_root == ws_checkpoint.root
    assert compute_epoch_at_slot(ws_state.slot) == ws_checkpoint.epoch

    ws_period = compute_weak_subjectivity_period(ws_state)  # [Modified in Electra]
    ws_state_epoch = compute_epoch_at_slot(ws_state.slot)
    current_epoch = compute_epoch_at_slot(get_current_slot(store))
    return current_epoch <= ws_state_epoch + ws_period


def get_sync_subcommittee_pubkeys(
    state: BeaconState, subcommittee_index: uint64
) -> Sequence[BLSPubkey]:
    # Committees assigned to `slot` sign for `slot - 1`
    # This creates the exceptional logic below when transitioning between sync committee periods
    next_slot_epoch = compute_epoch_at_slot(Slot(state.slot + 1))
    if compute_sync_committee_period(
        get_current_epoch(state)
    ) == compute_sync_committee_period(next_slot_epoch):
        sync_committee = state.current_sync_committee
    else:
        sync_committee = state.next_sync_committee

    # Return pubkeys for the subcommittee index
    sync_subcommittee_size = SYNC_COMMITTEE_SIZE // SYNC_COMMITTEE_SUBNET_COUNT
    i = subcommittee_index * sync_subcommittee_size
    return sync_committee.pubkeys[i : i + sync_subcommittee_size]


def is_assigned_to_sync_committee(
    state: BeaconState, epoch: Epoch, validator_index: ValidatorIndex
) -> bool:
    sync_committee_period = compute_sync_committee_period(epoch)
    current_epoch = get_current_epoch(state)
    current_sync_committee_period = compute_sync_committee_period(current_epoch)
    next_sync_committee_period = current_sync_committee_period + 1
    assert sync_committee_period in (
        current_sync_committee_period,
        next_sync_committee_period,
    )

    pubkey = state.validators[validator_index].pubkey
    if sync_committee_period == current_sync_committee_period:
        return pubkey in state.current_sync_committee.pubkeys
    else:  # sync_committee_period == next_sync_committee_period
        return pubkey in state.next_sync_committee.pubkeys


def process_sync_committee_contributions(
    block: BeaconBlock, contributions: Set[SyncCommitteeContribution]
) -> None:
    sync_aggregate = SyncAggregate()
    signatures = []
    sync_subcommittee_size = SYNC_COMMITTEE_SIZE // SYNC_COMMITTEE_SUBNET_COUNT

    for contribution in contributions:
        subcommittee_index = contribution.subcommittee_index
        for index, participated in enumerate(contribution.aggregation_bits):
            if participated:
                participant_index = sync_subcommittee_size * subcommittee_index + index
                sync_aggregate.sync_committee_bits[participant_index] = True
        signatures.append(contribution.signature)

    sync_aggregate.sync_committee_signature = bls.Aggregate(signatures)

    block.body.sync_aggregate = sync_aggregate


def get_sync_committee_message(
    state: BeaconState, block_root: Root, validator_index: ValidatorIndex, privkey: int
) -> SyncCommitteeMessage:
    epoch = get_current_epoch(state)
    domain = get_domain(state, DOMAIN_SYNC_COMMITTEE, epoch)
    signing_root = compute_signing_root(block_root, domain)
    signature = bls.Sign(privkey, signing_root)

    return SyncCommitteeMessage(
        slot=state.slot,
        beacon_block_root=block_root,
        validator_index=validator_index,
        signature=signature,
    )


def compute_subnets_for_sync_committee(
    state: BeaconState, validator_index: ValidatorIndex
) -> Set[SubnetID]:
    next_slot_epoch = compute_epoch_at_slot(Slot(state.slot + 1))
    if compute_sync_committee_period(
        get_current_epoch(state)
    ) == compute_sync_committee_period(next_slot_epoch):
        sync_committee = state.current_sync_committee
    else:
        sync_committee = state.next_sync_committee

    target_pubkey = state.validators[validator_index].pubkey
    sync_committee_indices = [
        index
        for index, pubkey in enumerate(sync_committee.pubkeys)
        if pubkey == target_pubkey
    ]
    return set(
        [
            SubnetID(index // (SYNC_COMMITTEE_SIZE // SYNC_COMMITTEE_SUBNET_COUNT))
            for index in sync_committee_indices
        ]
    )


def get_sync_committee_selection_proof(
    state: BeaconState, slot: Slot, subcommittee_index: uint64, privkey: int
) -> BLSSignature:
    domain = get_domain(
        state, DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF, compute_epoch_at_slot(slot)
    )
    signing_data = SyncAggregatorSelectionData(
        slot=slot,
        subcommittee_index=subcommittee_index,
    )
    signing_root = compute_signing_root(signing_data, domain)
    return bls.Sign(privkey, signing_root)


def is_sync_committee_aggregator(signature: BLSSignature) -> bool:
    modulo = max(
        1,
        SYNC_COMMITTEE_SIZE
        // SYNC_COMMITTEE_SUBNET_COUNT
        // TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE,
    )
    return bytes_to_uint64(hash(signature)[0:8]) % modulo == 0


def get_contribution_and_proof(
    state: BeaconState,
    aggregator_index: ValidatorIndex,
    contribution: SyncCommitteeContribution,
    privkey: int,
) -> ContributionAndProof:
    selection_proof = get_sync_committee_selection_proof(
        state,
        contribution.slot,
        contribution.subcommittee_index,
        privkey,
    )
    return ContributionAndProof(
        aggregator_index=aggregator_index,
        contribution=contribution,
        selection_proof=selection_proof,
    )


def get_contribution_and_proof_signature(
    state: BeaconState, contribution_and_proof: ContributionAndProof, privkey: int
) -> BLSSignature:
    contribution = contribution_and_proof.contribution
    domain = get_domain(
        state, DOMAIN_CONTRIBUTION_AND_PROOF, compute_epoch_at_slot(contribution.slot)
    )
    signing_root = compute_signing_root(contribution_and_proof, domain)
    return bls.Sign(privkey, signing_root)


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


def create_light_client_bootstrap(
    state: BeaconState, block: SignedBeaconBlock
) -> LightClientBootstrap:
    assert compute_epoch_at_slot(state.slot) >= config.ALTAIR_FORK_EPOCH

    assert state.slot == state.latest_block_header.slot
    header = state.latest_block_header.copy()
    header.state_root = hash_tree_root(state)
    assert hash_tree_root(header) == hash_tree_root(block.message)

    return LightClientBootstrap(
        header=block_to_light_client_header(block),
        current_sync_committee=state.current_sync_committee,
        current_sync_committee_branch=CurrentSyncCommitteeBranch(
            compute_merkle_proof(
                state, current_sync_committee_gindex_at_slot(state.slot)
            )
        ),
    )


def create_light_client_update(
    state: BeaconState,
    block: SignedBeaconBlock,
    attested_state: BeaconState,
    attested_block: SignedBeaconBlock,
    finalized_block: Optional[SignedBeaconBlock],
) -> LightClientUpdate:
    assert compute_epoch_at_slot(attested_state.slot) >= config.ALTAIR_FORK_EPOCH
    assert (
        sum(block.message.body.sync_aggregate.sync_committee_bits)
        >= MIN_SYNC_COMMITTEE_PARTICIPANTS
    )

    assert state.slot == state.latest_block_header.slot
    header = state.latest_block_header.copy()
    header.state_root = hash_tree_root(state)
    assert hash_tree_root(header) == hash_tree_root(block.message)
    update_signature_period = compute_sync_committee_period_at_slot(block.message.slot)

    assert attested_state.slot == attested_state.latest_block_header.slot
    attested_header = attested_state.latest_block_header.copy()
    attested_header.state_root = hash_tree_root(attested_state)
    assert (
        hash_tree_root(attested_header)
        == hash_tree_root(attested_block.message)
        == block.message.parent_root
    )
    update_attested_period = compute_sync_committee_period_at_slot(
        attested_block.message.slot
    )

    update = LightClientUpdate()

    update.attested_header = block_to_light_client_header(attested_block)

    # `next_sync_committee` is only useful if the message is signed by the current sync committee
    if update_attested_period == update_signature_period:
        update.next_sync_committee = attested_state.next_sync_committee
        update.next_sync_committee_branch = NextSyncCommitteeBranch(
            compute_merkle_proof(
                attested_state, next_sync_committee_gindex_at_slot(attested_state.slot)
            )
        )

    # Indicate finality whenever possible
    if finalized_block is not None:
        if finalized_block.message.slot != GENESIS_SLOT:
            update.finalized_header = block_to_light_client_header(finalized_block)
            assert (
                hash_tree_root(update.finalized_header.beacon)
                == attested_state.finalized_checkpoint.root
            )
        else:
            assert attested_state.finalized_checkpoint.root == Bytes32()
        update.finality_branch = FinalityBranch(
            compute_merkle_proof(
                attested_state, finalized_root_gindex_at_slot(attested_state.slot)
            )
        )

    update.sync_aggregate = block.message.body.sync_aggregate
    update.signature_slot = block.message.slot

    return update


def create_light_client_finality_update(
    update: LightClientUpdate,
) -> LightClientFinalityUpdate:
    return LightClientFinalityUpdate(
        attested_header=update.attested_header,
        finalized_header=update.finalized_header,
        finality_branch=update.finality_branch,
        sync_aggregate=update.sync_aggregate,
        signature_slot=update.signature_slot,
    )


def create_light_client_optimistic_update(
    update: LightClientUpdate,
) -> LightClientOptimisticUpdate:
    return LightClientOptimisticUpdate(
        attested_header=update.attested_header,
        sync_aggregate=update.sync_aggregate,
        signature_slot=update.signature_slot,
    )


def current_sync_committee_gindex_at_slot(slot: Slot) -> GeneralizedIndex:
    epoch = compute_epoch_at_slot(slot)

    # [Modified in Electra]
    if epoch >= config.ELECTRA_FORK_EPOCH:
        return CURRENT_SYNC_COMMITTEE_GINDEX_ELECTRA
    return CURRENT_SYNC_COMMITTEE_GINDEX


def initialize_light_client_store(
    trusted_block_root: Root, bootstrap: LightClientBootstrap
) -> LightClientStore:
    assert is_valid_light_client_header(bootstrap.header)
    assert hash_tree_root(bootstrap.header.beacon) == trusted_block_root

    assert is_valid_normalized_merkle_branch(
        leaf=hash_tree_root(bootstrap.current_sync_committee),
        branch=bootstrap.current_sync_committee_branch,
        gindex=current_sync_committee_gindex_at_slot(bootstrap.header.beacon.slot),
        root=bootstrap.header.beacon.state_root,
    )

    return LightClientStore(
        finalized_header=bootstrap.header,
        current_sync_committee=bootstrap.current_sync_committee,
        next_sync_committee=SyncCommittee(),
        best_valid_update=None,
        optimistic_header=bootstrap.header,
        previous_max_active_participants=0,
        current_max_active_participants=0,
    )


def is_merge_transition_complete(state: BeaconState) -> bool:
    return state.latest_execution_payload_header != ExecutionPayloadHeader()


def is_merge_transition_block(state: BeaconState, body: BeaconBlockBody) -> bool:
    return (
        not is_merge_transition_complete(state)
        and body.execution_payload != ExecutionPayload()
    )


def is_execution_enabled(state: BeaconState, body: BeaconBlockBody) -> bool:
    return is_merge_transition_block(state, body) or is_merge_transition_complete(state)


# 特殊, storeを引数に持ちながら間接的にstateを変更してる, 未着手
# def should_override_forkchoice_update(store: Store, head_root: Root) -> bool:
#     head_block = store.blocks[head_root]
#     parent_root = head_block.parent_root
#     parent_block = store.blocks[parent_root]
#     current_slot = get_current_slot(store)
#     proposal_slot = head_block.slot + Slot(1)

#     # Only re-org the head_block block if it arrived later than the attestation deadline.
#     head_late = is_head_late(store, head_root)

#     # Shuffling stable.
#     shuffling_stable = is_shuffling_stable(proposal_slot)

#     # FFG information of the new head_block will be competitive with the current head.
#     ffg_competitive = is_ffg_competitive(store, head_root, parent_root)

#     # Do not re-org if the chain is not finalizing with acceptable frequency.
#     finalization_ok = is_finalization_ok(store, proposal_slot)

#     # Only suppress the fork choice update if we are confident that we will propose the next block.
#     parent_state_advanced = store.block_states[parent_root].copy()
#     process_slots(parent_state_advanced, proposal_slot)
#     proposer_index = get_beacon_proposer_index(parent_state_advanced)
#     proposing_reorg_slot = validator_is_connected(proposer_index)

#     # Single slot re-org.
#     parent_slot_ok = parent_block.slot + 1 == head_block.slot
#     proposing_on_time = is_proposing_on_time(store)

#     # Note that this condition is different from `get_proposer_head`
#     current_time_ok = head_block.slot == current_slot or (
#         proposal_slot == current_slot and proposing_on_time
#     )
#     single_slot_reorg = parent_slot_ok and current_time_ok

#     # Check the head weight only if the attestations from the head slot have already been applied.
#     # Implementations may want to do this in different ways, e.g. by advancing
#     # `store.time` early, or by counting queued attestations during the head block's slot.
#     if current_slot > head_block.slot:
#         head_weak = is_head_weak(store, head_root)
#         parent_strong = is_parent_strong(store, parent_root)
#     else:
#         head_weak = True
#         parent_strong = True

#     return all(
#         [
#             head_late,
#             shuffling_stable,
#             ffg_competitive,
#             finalization_ok,
#             proposing_reorg_slot,
#             single_slot_reorg,
#             head_weak,
#             parent_strong,
#         ]
#     )


def is_valid_terminal_pow_block(block: PowBlock, parent: PowBlock) -> bool:
    is_total_difficulty_reached = (
        block.total_difficulty >= config.TERMINAL_TOTAL_DIFFICULTY
    )
    is_parent_total_difficulty_valid = (
        parent.total_difficulty < config.TERMINAL_TOTAL_DIFFICULTY
    )
    return is_total_difficulty_reached and is_parent_total_difficulty_valid


def validate_merge_block(block: BeaconBlock) -> None:
    """
    Check the parent PoW block of execution payload is a valid terminal PoW block.

    Note: Unavailable PoW block(s) may later become available,
    and a client software MAY delay a call to ``validate_merge_block``
    until the PoW block(s) become available.
    """
    if config.TERMINAL_BLOCK_HASH != Hash32():
        # If `config.TERMINAL_BLOCK_HASH` is used as an override, the activation epoch must be reached.
        assert (
            compute_epoch_at_slot(block.slot)
            >= config.TERMINAL_BLOCK_HASH_ACTIVATION_EPOCH
        )
        assert block.body.execution_payload.parent_hash == config.TERMINAL_BLOCK_HASH
        return

    pow_block = get_pow_block(block.body.execution_payload.parent_hash)
    # Check if `pow_block` is available
    assert pow_block is not None
    pow_parent = get_pow_block(pow_block.parent_hash)
    # Check if `pow_parent` is available
    assert pow_parent is not None
    # Check if `pow_block` is a valid terminal PoW block
    assert is_valid_terminal_pow_block(pow_block, pow_parent)


def get_pow_block_at_terminal_total_difficulty(
    pow_chain: Dict[Hash32, PowBlock],
) -> Optional[PowBlock]:
    # `pow_chain` abstractly represents all blocks in the PoW chain
    for block in pow_chain.values():
        block_reached_ttd = block.total_difficulty >= config.TERMINAL_TOTAL_DIFFICULTY
        if block_reached_ttd:
            # If genesis block, no parent exists so reaching TTD alone qualifies as valid terminal block
            if block.parent_hash == Hash32():
                return block
            parent = pow_chain[block.parent_hash]
            parent_reached_ttd = (
                parent.total_difficulty >= config.TERMINAL_TOTAL_DIFFICULTY
            )
            if not parent_reached_ttd:
                return block

    return None


def get_terminal_pow_block(pow_chain: Dict[Hash32, PowBlock]) -> Optional[PowBlock]:
    if config.TERMINAL_BLOCK_HASH != Hash32():
        # Terminal block hash override takes precedence over terminal total difficulty
        if config.TERMINAL_BLOCK_HASH in pow_chain:
            return pow_chain[config.TERMINAL_BLOCK_HASH]
        else:
            return None

    return get_pow_block_at_terminal_total_difficulty(pow_chain)


def prepare_execution_payload(
    state: BeaconState,
    safe_block_hash: Hash32,
    finalized_block_hash: Hash32,
    suggested_fee_recipient: ExecutionAddress,
    execution_engine: ExecutionEngine,
) -> Optional[PayloadId]:
    # Verify consistency of the parent hash with respect to the previous execution payload header
    parent_hash = state.latest_execution_payload_header.block_hash

    # Set the forkchoice head and initiate the payload build process
    withdrawals, _ = get_expected_withdrawals(state)  # [Modified in EIP-7251]

    payload_attributes = PayloadAttributes(
        timestamp=compute_timestamp_at_slot(state, state.slot),
        prev_randao=get_randao_mix(state, get_current_epoch(state)),
        suggested_fee_recipient=suggested_fee_recipient,
        withdrawals=withdrawals,
        parent_beacon_block_root=hash_tree_root(state.latest_block_header),
    )
    return execution_engine.notify_forkchoice_updated(
        head_block_hash=parent_hash,
        safe_block_hash=safe_block_hash,
        finalized_block_hash=finalized_block_hash,
        payload_attributes=payload_attributes,
    )


def get_execution_payload(
    payload_id: Optional[PayloadId], execution_engine: ExecutionEngine
) -> ExecutionPayload:
    if payload_id is None:
        # Pre-merge, empty payload
        return ExecutionPayload()
    else:
        return execution_engine.get_payload(payload_id).execution_payload


def is_optimistic(opt_store: OptimisticStore, block: BeaconBlock) -> bool:
    return hash_tree_root(block) in opt_store.optimistic_roots


def latest_verified_ancestor(
    opt_store: OptimisticStore, block: BeaconBlock
) -> BeaconBlock:
    # It is assumed that the `block` parameter is never an INVALIDATED block.
    while True:
        if not is_optimistic(opt_store, block) or block.parent_root == Root():
            return block
        block = opt_store.blocks[block.parent_root]


def is_execution_block(block: BeaconBlock) -> bool:
    return block.body.execution_payload != ExecutionPayload()


def is_optimistic_candidate_block(
    opt_store: OptimisticStore, current_slot: Slot, block: BeaconBlock
) -> bool:
    if is_execution_block(opt_store.blocks[block.parent_root]):
        return True

    if block.slot + SAFE_SLOTS_TO_IMPORT_OPTIMISTICALLY <= current_slot:
        return True

    return False


def get_validator_activation_churn_limit(state: BeaconState) -> uint64:
    """
    Return the validator activation churn limit for the current epoch.
    """
    return min(
        config.MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT, get_validator_churn_limit(state)
    )


def multi_exp(
    _points: Sequence[TPoint], _integers: Sequence[uint64]
) -> Sequence[TPoint]: ...


def blob_to_kzg_commitment(blob: Blob) -> KZGCommitment:
    """
    Public method.
    """
    assert len(blob) == BYTES_PER_BLOB
    return g1_lincomb(
        bit_reversal_permutation(KZG_SETUP_G1_LAGRANGE), blob_to_polynomial(blob)
    )


def verify_kzg_proof(
    commitment_bytes: Bytes48, z_bytes: Bytes32, y_bytes: Bytes32, proof_bytes: Bytes48
) -> bool:
    """
    Verify KZG proof that ``p(z) == y`` where ``p(z)`` is the polynomial represented by ``polynomial_kzg``.
    Receives inputs as bytes.
    Public method.
    """
    assert len(commitment_bytes) == BYTES_PER_COMMITMENT
    assert len(z_bytes) == BYTES_PER_FIELD_ELEMENT
    assert len(y_bytes) == BYTES_PER_FIELD_ELEMENT
    assert len(proof_bytes) == BYTES_PER_PROOF

    return verify_kzg_proof_impl(
        bytes_to_kzg_commitment(commitment_bytes),
        bytes_to_bls_field(z_bytes),
        bytes_to_bls_field(y_bytes),
        bytes_to_kzg_proof(proof_bytes),
    )


def verify_kzg_proof_impl(
    commitment: KZGCommitment, z: BLSFieldElement, y: BLSFieldElement, proof: KZGProof
) -> bool:
    """
    Verify KZG proof that ``p(z) == y`` where ``p(z)`` is the polynomial represented by ``polynomial_kzg``.
    """
    # Verify: P - y = Q * (X - z)
    X_minus_z = bls.add(
        bls.bytes96_to_G2(KZG_SETUP_G2_MONOMIAL[1]),
        bls.multiply(bls.G2(), -z),
    )
    P_minus_y = bls.add(bls.bytes48_to_G1(commitment), bls.multiply(bls.G1(), -y))
    return bls.pairing_check(
        [[P_minus_y, bls.neg(bls.G2())], [bls.bytes48_to_G1(proof), X_minus_z]]
    )


def compute_kzg_proof(blob: Blob, z_bytes: Bytes32) -> Tuple[KZGProof, Bytes32]:
    """
    Compute KZG proof at point `z` for the polynomial represented by `blob`.
    Do this by computing the quotient polynomial in evaluation form: q(x) = (p(x) - p(z)) / (x - z).
    Public method.
    """
    assert len(blob) == BYTES_PER_BLOB
    assert len(z_bytes) == BYTES_PER_FIELD_ELEMENT
    polynomial = blob_to_polynomial(blob)
    proof, y = compute_kzg_proof_impl(polynomial, bytes_to_bls_field(z_bytes))
    return proof, int(y).to_bytes(BYTES_PER_FIELD_ELEMENT, KZG_ENDIANNESS)


def compute_quotient_eval_within_domain(
    z: BLSFieldElement, polynomial: Polynomial, y: BLSFieldElement
) -> BLSFieldElement:
    """
    Given `y == p(z)` for a polynomial `p(x)`, compute `q(z)`: the KZG quotient polynomial evaluated at `z` for the
    special case where `z` is in roots of unity.

    For more details, read https://dankradfeist.de/ethereum/2021/06/18/pcs-multiproofs.html section "Dividing
    when one of the points is zero". The code below computes q(x_m) for the roots of unity special case.
    """
    roots_of_unity_brp = bit_reversal_permutation(
        compute_roots_of_unity(FIELD_ELEMENTS_PER_BLOB)
    )
    result = BLSFieldElement(0)
    for i, omega_i in enumerate(roots_of_unity_brp):
        if omega_i == z:  # skip the evaluation point in the sum
            continue

        f_i = polynomial[i] - y
        numerator = f_i * omega_i
        denominator = z * (z - omega_i)
        result += numerator / denominator

    return result


def compute_kzg_proof_impl(
    polynomial: Polynomial, z: BLSFieldElement
) -> Tuple[KZGProof, BLSFieldElement]:
    """
    Helper function for `compute_kzg_proof()` and `compute_blob_kzg_proof()`.
    """
    roots_of_unity_brp = bit_reversal_permutation(
        compute_roots_of_unity(FIELD_ELEMENTS_PER_BLOB)
    )

    # For all x_i, compute p(x_i) - p(z)
    y = evaluate_polynomial_in_evaluation_form(polynomial, z)
    polynomial_shifted = [p - y for p in polynomial]

    # For all x_i, compute (x_i - z)
    denominator_poly = [x - z for x in roots_of_unity_brp]

    # Compute the quotient polynomial directly in evaluation form
    quotient_polynomial = [BLSFieldElement(0)] * FIELD_ELEMENTS_PER_BLOB
    for i, (a, b) in enumerate(zip(polynomial_shifted, denominator_poly)):
        if b == BLSFieldElement(0):
            # The denominator is zero hence `z` is a root of unity: we must handle it as a special case
            quotient_polynomial[i] = compute_quotient_eval_within_domain(
                roots_of_unity_brp[i], polynomial, y
            )
        else:
            # Compute: q(x_i) = (p(x_i) - p(z)) / (x_i - z).
            quotient_polynomial[i] = a / b

    return KZGProof(
        g1_lincomb(bit_reversal_permutation(KZG_SETUP_G1_LAGRANGE), quotient_polynomial)
    ), y


def compute_blob_kzg_proof(blob: Blob, commitment_bytes: Bytes48) -> KZGProof:
    """
    Given a blob, return the KZG proof that is used to verify it against the commitment.
    This method does not verify that the commitment is correct with respect to `blob`.
    Public method.
    """
    assert len(blob) == BYTES_PER_BLOB
    assert len(commitment_bytes) == BYTES_PER_COMMITMENT
    commitment = bytes_to_kzg_commitment(commitment_bytes)
    polynomial = blob_to_polynomial(blob)
    evaluation_challenge = compute_challenge(blob, commitment)
    proof, _ = compute_kzg_proof_impl(polynomial, evaluation_challenge)
    return proof


def verify_blob_kzg_proof(
    blob: Blob, commitment_bytes: Bytes48, proof_bytes: Bytes48
) -> bool:
    """
    Given a blob and a KZG proof, verify that the blob data corresponds to the provided commitment.

    Public method.
    """
    assert len(blob) == BYTES_PER_BLOB
    assert len(commitment_bytes) == BYTES_PER_COMMITMENT
    assert len(proof_bytes) == BYTES_PER_PROOF

    commitment = bytes_to_kzg_commitment(commitment_bytes)

    polynomial = blob_to_polynomial(blob)
    evaluation_challenge = compute_challenge(blob, commitment)

    # Evaluate polynomial at `evaluation_challenge`
    y = evaluate_polynomial_in_evaluation_form(polynomial, evaluation_challenge)

    # Verify proof
    proof = bytes_to_kzg_proof(proof_bytes)
    return verify_kzg_proof_impl(commitment, evaluation_challenge, y, proof)


def verify_blob_sidecar_inclusion_proof(blob_sidecar: BlobSidecar) -> bool:
    gindex = get_subtree_index(
        get_generalized_index(
            BeaconBlockBody, "blob_kzg_commitments", blob_sidecar.index
        )
    )
    return is_valid_merkle_branch(
        leaf=blob_sidecar.kzg_commitment.hash_tree_root(),
        branch=blob_sidecar.kzg_commitment_inclusion_proof,
        depth=KZG_COMMITMENT_INCLUSION_PROOF_DEPTH,
        index=gindex,
        root=blob_sidecar.signed_block_header.message.body_root,
    )


def compute_signed_block_header(
    signed_block: SignedBeaconBlock,
) -> SignedBeaconBlockHeader:
    block = signed_block.message
    block_header = BeaconBlockHeader(
        slot=block.slot,
        proposer_index=block.proposer_index,
        parent_root=block.parent_root,
        state_root=block.state_root,
        body_root=hash_tree_root(block.body),
    )
    return SignedBeaconBlockHeader(
        message=block_header, signature=signed_block.signature
    )


def get_blob_sidecars(
    signed_block: SignedBeaconBlock,
    blobs: Sequence[Blob],
    blob_kzg_proofs: Sequence[KZGProof],
) -> Sequence[BlobSidecar]:
    block = signed_block.message
    signed_block_header = compute_signed_block_header(signed_block)
    return [
        BlobSidecar(
            index=index,
            blob=blob,
            kzg_commitment=block.body.blob_kzg_commitments[index],
            kzg_proof=blob_kzg_proofs[index],
            signed_block_header=signed_block_header,
            kzg_commitment_inclusion_proof=compute_merkle_proof(
                block.body,
                get_generalized_index(BeaconBlockBody, "blob_kzg_commitments", index),
            ),
        )
        for index, blob in enumerate(blobs)
    ]


def compute_subnet_for_blob_sidecar(blob_index: BlobIndex) -> SubnetID:
    return SubnetID(blob_index % config.BLOB_SIDECAR_SUBNET_COUNT_ELECTRA)


def get_execution_requests_list(
    execution_requests: ExecutionRequests,
) -> Sequence[bytes]:
    requests = [
        (DEPOSIT_REQUEST_TYPE, execution_requests.deposits),
        (WITHDRAWAL_REQUEST_TYPE, execution_requests.withdrawals),
        (CONSOLIDATION_REQUEST_TYPE, execution_requests.consolidations),
    ]

    return [
        request_type + ssz_serialize(request_data)
        for request_type, request_data in requests
        if len(request_data) != 0
    ]


def compute_on_chain_aggregate(
    network_aggregates: Sequence[Attestation],
) -> Attestation:
    aggregates = sorted(
        network_aggregates, key=lambda a: get_committee_indices(a.committee_bits)[0]
    )

    data = aggregates[0].data
    aggregation_bits = Bitlist[MAX_VALIDATORS_PER_COMMITTEE * MAX_COMMITTEES_PER_SLOT]()
    for a in aggregates:
        for b in a.aggregation_bits:
            aggregation_bits.append(b)

    signature = bls.Aggregate([a.signature for a in aggregates])

    committee_indices = [get_committee_indices(a.committee_bits)[0] for a in aggregates]
    committee_flags = [
        (index in committee_indices) for index in range(0, MAX_COMMITTEES_PER_SLOT)
    ]
    committee_bits = Bitvector[MAX_COMMITTEES_PER_SLOT](committee_flags)

    return Attestation(
        aggregation_bits=aggregation_bits,
        data=data,
        committee_bits=committee_bits,
        signature=signature,
    )


def get_eth1_pending_deposit_count(state: BeaconState) -> uint64:
    eth1_deposit_index_limit = min(
        state.eth1_data.deposit_count, state.deposit_requests_start_index
    )
    if state.eth1_deposit_index < eth1_deposit_index_limit:
        return min(MAX_DEPOSITS, eth1_deposit_index_limit - state.eth1_deposit_index)
    else:
        return uint64(0)


def get_execution_requests(
    execution_requests_list: Sequence[bytes],
) -> ExecutionRequests:
    deposits = []
    withdrawals = []
    consolidations = []

    request_types = [
        DEPOSIT_REQUEST_TYPE,
        WITHDRAWAL_REQUEST_TYPE,
        CONSOLIDATION_REQUEST_TYPE,
    ]

    prev_request_type = None
    for request in execution_requests_list:
        request_type, request_data = request[0:1], request[1:]

        # Check that the request type is valid
        assert request_type in request_types
        # Check that the request data is not empty
        assert len(request_data) != 0
        # Check that requests are in strictly ascending order
        # Each successive type must be greater than the last with no duplicates
        assert prev_request_type is None or prev_request_type < request_type
        prev_request_type = request_type

        if request_type == DEPOSIT_REQUEST_TYPE:
            deposits = ssz_deserialize(
                List[DepositRequest, MAX_DEPOSIT_REQUESTS_PER_PAYLOAD], request_data
            )
        elif request_type == WITHDRAWAL_REQUEST_TYPE:
            withdrawals = ssz_deserialize(
                List[WithdrawalRequest, MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD],
                request_data,
            )
        elif request_type == CONSOLIDATION_REQUEST_TYPE:
            consolidations = ssz_deserialize(
                List[ConsolidationRequest, MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD],
                request_data,
            )

    return ExecutionRequests(
        deposits=deposits,
        withdrawals=withdrawals,
        consolidations=consolidations,
    )


def normalize_merkle_branch(
    branch: Sequence[Bytes32], gindex: GeneralizedIndex
) -> Sequence[Bytes32]:
    depth = floorlog2(gindex)
    num_extra = depth - len(branch)
    return [Bytes32()] * num_extra + [*branch]


def get_eth1_data(block: Eth1Block) -> Eth1Data:
    """
    A stub function return mocking Eth1Data.
    """
    return Eth1Data(
        deposit_root=block.deposit_root,
        deposit_count=block.deposit_count,
        block_hash=hash_tree_root(block),
    )


def cache_this(key_fn, value_fn, lru_size):  # type: ignore
    cache_dict = LRU(size=lru_size)

    def wrapper(*args, **kw):  # type: ignore
        key = key_fn(*args, **kw)
        if key not in cache_dict:
            cache_dict[key] = value_fn(*args, **kw)
        return cache_dict[key]

    return wrapper


_compute_shuffled_index = compute_shuffled_index
compute_shuffled_index = cache_this(
    lambda index, index_count, seed: (index, index_count, seed),
    _compute_shuffled_index,
    lru_size=SLOTS_PER_EPOCH * 3,
)

_get_total_active_balance = get_total_active_balance
get_total_active_balance = cache_this(
    lambda state: (
        state.validators.hash_tree_root(),
        compute_epoch_at_slot(state.slot),
    ),
    _get_total_active_balance,
    lru_size=10,
)

_get_base_reward = get_base_reward
get_base_reward = cache_this(
    lambda state, index: (state.validators.hash_tree_root(), state.slot, index),
    _get_base_reward,
    lru_size=2048,
)

_get_committee_count_per_slot = get_committee_count_per_slot
get_committee_count_per_slot = cache_this(
    lambda state, epoch: (state.validators.hash_tree_root(), epoch),
    _get_committee_count_per_slot,
    lru_size=SLOTS_PER_EPOCH * 3,
)

_get_active_validator_indices = get_active_validator_indices
get_active_validator_indices = cache_this(
    lambda state, epoch: (state.validators.hash_tree_root(), epoch),
    _get_active_validator_indices,
    lru_size=3,
)

_get_beacon_committee = get_beacon_committee
get_beacon_committee = cache_this(
    lambda state, slot, index: (
        state.validators.hash_tree_root(),
        state.randao_mixes.hash_tree_root(),
        slot,
        index,
    ),
    _get_beacon_committee,
    lru_size=SLOTS_PER_EPOCH * MAX_COMMITTEES_PER_SLOT * 3,
)

_get_matching_target_attestations = get_matching_target_attestations
get_matching_target_attestations = cache_this(
    lambda state, epoch: (state.hash_tree_root(), epoch),
    _get_matching_target_attestations,
    lru_size=10,
)

_get_matching_head_attestations = get_matching_head_attestations
get_matching_head_attestations = cache_this(
    lambda state, epoch: (state.hash_tree_root(), epoch),
    _get_matching_head_attestations,
    lru_size=10,
)

_get_attesting_indices = get_attesting_indices
get_attesting_indices = cache_this(
    lambda state, attestation: (
        state.randao_mixes.hash_tree_root(),
        state.validators.hash_tree_root(),
        attestation.hash_tree_root(),
    ),
    _get_attesting_indices,
    lru_size=SLOTS_PER_EPOCH * MAX_COMMITTEES_PER_SLOT * 3,
)


def get_generalized_index(
    ssz_class: Any, *path: PyUnion[int, SSZVariableName]
) -> GeneralizedIndex:
    ssz_path = Path(ssz_class)
    for item in path:
        ssz_path = ssz_path / item
    return GeneralizedIndex(ssz_path.gindex())


def compute_merkle_proof(object: SSZObject, index: GeneralizedIndex) -> list[Bytes32]:
    return build_proof(object.get_backing(), index)


ExecutionState = Any


def get_pow_block(hash: Bytes32) -> Optional[PowBlock]:
    return PowBlock(block_hash=hash, parent_hash=Bytes32(), total_difficulty=uint256(0))


def get_execution_state(_execution_state_root: Bytes32) -> ExecutionState:
    pass


def get_pow_chain_head() -> PowBlock:
    pass


def validator_is_connected(validator_index: ValidatorIndex) -> bool:
    # pylint: disable=unused-argument
    return True


assert FINALIZED_ROOT_GINDEX == get_generalized_index(
    altair.BeaconState, "finalized_checkpoint", "root"
)
assert CURRENT_SYNC_COMMITTEE_GINDEX == get_generalized_index(
    altair.BeaconState, "current_sync_committee"
)
assert NEXT_SYNC_COMMITTEE_GINDEX == get_generalized_index(
    altair.BeaconState, "next_sync_committee"
)
assert EXECUTION_PAYLOAD_GINDEX == get_generalized_index(
    BeaconBlockBody, "execution_payload"
)
assert FINALIZED_ROOT_GINDEX_ELECTRA == get_generalized_index(
    BeaconState, "finalized_checkpoint", "root"
)
assert CURRENT_SYNC_COMMITTEE_GINDEX_ELECTRA == get_generalized_index(
    BeaconState, "current_sync_committee"
)
assert NEXT_SYNC_COMMITTEE_GINDEX_ELECTRA == get_generalized_index(
    BeaconState, "next_sync_committee"
)


assert KZG_COMMITMENT_INCLUSION_PROOF_DEPTH == uint64(
    floorlog2(get_generalized_index(BeaconBlockBody, "blob_kzg_commitments"))
    + 1
    + ceillog2(MAX_BLOB_COMMITMENTS_PER_BLOCK)
)  # noqa: E501

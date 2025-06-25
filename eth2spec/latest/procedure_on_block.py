from typing import Tuple

from eth2spec.utils.ssz.ssz_impl import hash_tree_root, copy

from eth2spec.latest.constants_0 import *
from eth2spec.latest.funcs_0 import *
from eth2spec.latest.classes_0 import *
from eth2spec.latest.constants_1 import *
from eth2spec.latest.classes_1 import *
from eth2spec.latest.funcs_1 import *
from eth2spec.latest.funcs_2 import *


def on_block(store: Store, signed_block: SignedBeaconBlock) -> None:
    """
    Run ``on_block`` upon receiving a new block.
    """
    block = signed_block.message
    # Parent block must be known
    assert block.parent_root in store.block_states
    # Blocks cannot be in the future. If they are, their consideration must be delayed until they are in the past.
    assert get_current_slot(store) >= block.slot

    # Check that block is later than the finalized epoch slot (optimization to reduce calls to get_ancestor)
    finalized_slot = compute_start_slot_at_epoch(store.finalized_checkpoint.epoch)
    assert block.slot > finalized_slot
    # Check block is a descendant of the finalized block at the checkpoint finalized slot
    finalized_checkpoint_block = get_checkpoint_block(
        store,
        block.parent_root,
        store.finalized_checkpoint.epoch,
    )
    assert store.finalized_checkpoint.root == finalized_checkpoint_block

    # [New in Deneb:EIP4844]
    # Check if blob data is available
    # If not, this block MAY be queued and subsequently considered when blob data becomes available
    # *Note*: Extraneous or invalid Blobs (in addition to the expected/referenced valid blobs)
    # received on the p2p network MUST NOT invalidate a block that is otherwise valid and available
    assert is_data_available(hash_tree_root(block), block.body.blob_kzg_commitments)

    # Check the block is valid and compute the post-state
    # Make a copy of the state to avoid mutability issues
    state = copy(store.block_states[block.parent_root])
    block_root = hash_tree_root(block)
    state_transition(state, signed_block, True)

    # Add new block to the store
    store.blocks[block_root] = block
    # Add new state for this block to the store
    store.block_states[block_root] = state

    # Add block timeliness to the store
    time_into_slot = (store.time - store.genesis_time) % config.SECONDS_PER_SLOT
    is_before_attesting_interval = (
        time_into_slot < config.SECONDS_PER_SLOT // INTERVALS_PER_SLOT
    )
    is_timely = get_current_slot(store) == block.slot and is_before_attesting_interval
    store.block_timeliness[hash_tree_root(block)] = is_timely

    # Add proposer score boost if the block is timely and not conflicting with an existing block
    is_first_block = store.proposer_boost_root == Root()
    if is_timely and is_first_block:
        store.proposer_boost_root = hash_tree_root(block)

    # Update checkpoints in store if necessary
    update_checkpoints(
        store, state.current_justified_checkpoint, state.finalized_checkpoint
    )

    # Eagerly compute unrealized justification and finality.
    compute_pulled_up_tip(store, block_root)


def compute_pulled_up_tip(store: Store, block_root: Root) -> None:
    state = store.block_states[block_root].copy()
    # Pull up the post-state of the block to the next epoch boundary
    process_justification_and_finalization(state)

    store.unrealized_justifications[block_root] = state.current_justified_checkpoint
    update_unrealized_checkpoints(
        store, state.current_justified_checkpoint, state.finalized_checkpoint
    )

    # If the block is from a prior epoch, apply the realized values
    block_epoch = compute_epoch_at_slot(store.blocks[block_root].slot)
    current_epoch = get_current_store_epoch(store)
    if block_epoch < current_epoch:
        update_checkpoints(
            store, state.current_justified_checkpoint, state.finalized_checkpoint
        )


def is_data_available(
    beacon_block_root: Root, blob_kzg_commitments: Sequence[KZGCommitment]
) -> bool:
    # `retrieve_blobs_and_proofs` is implementation and context dependent
    # It returns all the blobs for the given block root, and raises an exception if not available
    # Note: the p2p network does not guarantee sidecar retrieval outside of
    # `config.MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS`
    blobs, proofs = retrieve_blobs_and_proofs(beacon_block_root)

    return verify_blob_kzg_proof_batch(blobs, blob_kzg_commitments, proofs)


def verify_blob_kzg_proof_batch(
    blobs: Sequence[Blob],
    commitments_bytes: Sequence[Bytes48],
    proofs_bytes: Sequence[Bytes48],
) -> bool:
    """
    Given a list of blobs and blob KZG proofs, verify that they correspond to the provided commitments.
    Will return True if there are zero blobs/commitments/proofs.
    Public method.
    """

    assert len(blobs) == len(commitments_bytes) == len(proofs_bytes)

    commitments, evaluation_challenges, ys, proofs = [], [], [], []
    for blob, commitment_bytes, proof_bytes in zip(
        blobs, commitments_bytes, proofs_bytes
    ):
        assert len(blob) == BYTES_PER_BLOB
        assert len(commitment_bytes) == BYTES_PER_COMMITMENT
        assert len(proof_bytes) == BYTES_PER_PROOF
        commitment = bytes_to_kzg_commitment(commitment_bytes)
        commitments.append(commitment)
        polynomial = blob_to_polynomial(blob)
        evaluation_challenge = compute_challenge(blob, commitment)
        evaluation_challenges.append(evaluation_challenge)
        ys.append(
            evaluate_polynomial_in_evaluation_form(polynomial, evaluation_challenge)
        )
        proofs.append(bytes_to_kzg_proof(proof_bytes))

    return verify_kzg_proof_batch(commitments, evaluation_challenges, ys, proofs)


def retrieve_blobs_and_proofs(
    beacon_block_root: Root,
) -> Tuple[Sequence[Blob], Sequence[KZGProof]]:
    # pylint: disable=unused-argument
    return [], []


def verify_kzg_proof_batch(
    commitments: Sequence[KZGCommitment],
    zs: Sequence[BLSFieldElement],
    ys: Sequence[BLSFieldElement],
    proofs: Sequence[KZGProof],
) -> bool:
    """
    Verify multiple KZG proofs efficiently.
    """

    assert len(commitments) == len(zs) == len(ys) == len(proofs)

    # Compute a random challenge. Note that it does not have to be computed from a hash,
    # r just has to be random.
    degree_poly = int.to_bytes(FIELD_ELEMENTS_PER_BLOB, 8, KZG_ENDIANNESS)
    num_commitments = int.to_bytes(len(commitments), 8, KZG_ENDIANNESS)
    data = RANDOM_CHALLENGE_KZG_BATCH_DOMAIN + degree_poly + num_commitments

    # Append all inputs to the transcript before we hash
    for commitment, z, y, proof in zip(commitments, zs, ys, proofs):
        data += commitment + bls_field_to_bytes(z) + bls_field_to_bytes(y) + proof

    r = hash_to_bls_field(data)
    r_powers = compute_powers(r, len(commitments))

    # Verify: e(sum r^i proof_i, [s]) ==
    # e(sum r^i (commitment_i - [y_i]) + sum r^i z_i proof_i, [1])
    proof_lincomb = g1_lincomb(proofs, r_powers)
    proof_z_lincomb = g1_lincomb(
        proofs, [z * r_power for z, r_power in zip(zs, r_powers)]
    )
    C_minus_ys = [
        bls.add(bls.bytes48_to_G1(commitment), bls.multiply(bls.G1(), -y))
        for commitment, y in zip(commitments, ys)
    ]
    C_minus_y_as_KZGCommitments = [
        KZGCommitment(bls.G1_to_bytes48(x)) for x in C_minus_ys
    ]
    C_minus_y_lincomb = g1_lincomb(C_minus_y_as_KZGCommitments, r_powers)

    return bls.pairing_check(
        [
            [
                bls.bytes48_to_G1(proof_lincomb),
                bls.neg(bls.bytes96_to_G2(KZG_SETUP_G2_MONOMIAL[1])),
            ],
            [
                bls.add(
                    bls.bytes48_to_G1(C_minus_y_lincomb),
                    bls.bytes48_to_G1(proof_z_lincomb),
                ),
                bls.G2(),
            ],
        ]
    )


def bls_field_to_bytes(x: BLSFieldElement) -> Bytes32:
    return int.to_bytes(int(x), 32, KZG_ENDIANNESS)


def update_unrealized_checkpoints(
    store: Store,
    unrealized_justified_checkpoint: Checkpoint,
    unrealized_finalized_checkpoint: Checkpoint,
) -> None:
    """
    Update unrealized checkpoints in store if necessary
    """
    # Update unrealized justified checkpoint
    if (
        unrealized_justified_checkpoint.epoch
        > store.unrealized_justified_checkpoint.epoch
    ):
        store.unrealized_justified_checkpoint = unrealized_justified_checkpoint

    # Update unrealized finalized checkpoint
    if (
        unrealized_finalized_checkpoint.epoch
        > store.unrealized_finalized_checkpoint.epoch
    ):
        store.unrealized_finalized_checkpoint = unrealized_finalized_checkpoint

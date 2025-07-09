# pyright: reportInvalidTypeForm=false

from dataclasses import dataclass, field
from typing import (
    Dict,
    Set,
    Sequence,
    Optional,
    Protocol,
)

from eth2spec.utils.ssz.ssz_typing import (
    boolean,
    Container,
    List,
    Vector,
    uint64,
    uint256,
    Bytes32,
    Bitlist,
    Bitvector,
    ByteList,
    ByteVector,
)

from eth2spec.latest_2.constants import *
from eth2spec.latest_2.classes import *


class Fork(Container):
    previous_version: Version
    current_version: Version
    epoch: Epoch


class ForkData(Container):
    current_version: Version
    genesis_validators_root: Root


class Checkpoint(Container):
    epoch: Epoch
    root: Root


class Validator(Container):
    pubkey: BLSPubkey
    withdrawal_credentials: Bytes32
    effective_balance: Gwei
    slashed: boolean
    activation_eligibility_epoch: Epoch
    activation_epoch: Epoch
    exit_epoch: Epoch
    withdrawable_epoch: Epoch


class AttestationData(Container):
    slot: Slot
    index: CommitteeIndex
    beacon_block_root: Root
    source: Checkpoint
    target: Checkpoint


class IndexedAttestation(Container):
    # [Modified in Electra:EIP7549]
    attesting_indices: List[
        ValidatorIndex, MAX_VALIDATORS_PER_COMMITTEE * MAX_COMMITTEES_PER_SLOT
    ]
    data: AttestationData
    signature: BLSSignature


class PendingAttestation(Container):
    aggregation_bits: Bitlist[MAX_VALIDATORS_PER_COMMITTEE]
    data: AttestationData
    inclusion_delay: Slot
    proposer_index: ValidatorIndex


class Eth1Data(Container):
    deposit_root: Root
    deposit_count: uint64
    block_hash: Hash32


class HistoricalBatch(Container):
    block_roots: Vector[Root, SLOTS_PER_HISTORICAL_ROOT]
    state_roots: Vector[Root, SLOTS_PER_HISTORICAL_ROOT]


class DepositMessage(Container):
    pubkey: BLSPubkey
    withdrawal_credentials: Bytes32
    amount: Gwei


class DepositData(Container):
    pubkey: BLSPubkey
    withdrawal_credentials: Bytes32
    amount: Gwei
    signature: BLSSignature


class BeaconBlockHeader(Container):
    slot: Slot
    proposer_index: ValidatorIndex
    parent_root: Root
    state_root: Root
    body_root: Root


class SigningData(Container):
    object_root: Root
    domain: Domain


class AttesterSlashing(Container):
    # [Modified in Electra:EIP7549]
    attestation_1: IndexedAttestation
    # [Modified in Electra:EIP7549]
    attestation_2: IndexedAttestation


class Attestation(Container):
    # [Modified in Electra:EIP7549]
    aggregation_bits: Bitlist[MAX_VALIDATORS_PER_COMMITTEE * MAX_COMMITTEES_PER_SLOT]
    data: AttestationData
    signature: BLSSignature
    # [New in Electra:EIP7549]
    committee_bits: Bitvector[MAX_COMMITTEES_PER_SLOT]


class Deposit(Container):
    proof: Vector[Bytes32, DEPOSIT_CONTRACT_TREE_DEPTH + 1]
    data: DepositData


class VoluntaryExit(Container):
    epoch: Epoch
    validator_index: ValidatorIndex


class SignedVoluntaryExit(Container):
    message: VoluntaryExit
    signature: BLSSignature


class SignedBeaconBlockHeader(Container):
    message: BeaconBlockHeader
    signature: BLSSignature


class ProposerSlashing(Container):
    signed_header_1: SignedBeaconBlockHeader
    signed_header_2: SignedBeaconBlockHeader


class Eth1Block(Container):
    timestamp: uint64
    deposit_root: Root
    deposit_count: uint64


class AggregateAndProof(Container):
    aggregator_index: ValidatorIndex
    # [Modified in Electra:EIP7549]
    aggregate: Attestation
    selection_proof: BLSSignature


class SignedAggregateAndProof(Container):
    # [Modified in Electra:EIP7549]
    message: AggregateAndProof
    signature: BLSSignature


class SyncAggregate(Container):
    sync_committee_bits: Bitvector[SYNC_COMMITTEE_SIZE]
    sync_committee_signature: BLSSignature


class SyncCommittee(Container):
    pubkeys: Vector[BLSPubkey, SYNC_COMMITTEE_SIZE]
    aggregate_pubkey: BLSPubkey


class SyncCommitteeMessage(Container):
    slot: Slot
    beacon_block_root: Root
    validator_index: ValidatorIndex
    signature: BLSSignature


class SyncCommitteeContribution(Container):
    slot: Slot
    beacon_block_root: Root
    subcommittee_index: uint64
    aggregation_bits: Bitvector[SYNC_COMMITTEE_SIZE // SYNC_COMMITTEE_SUBNET_COUNT]
    signature: BLSSignature


class ContributionAndProof(Container):
    aggregator_index: ValidatorIndex
    contribution: SyncCommitteeContribution
    selection_proof: BLSSignature


class SignedContributionAndProof(Container):
    message: ContributionAndProof
    signature: BLSSignature


class SyncAggregatorSelectionData(Container):
    slot: Slot
    subcommittee_index: uint64


class ExecutionPayloadHeader(Container):
    parent_hash: Hash32
    fee_recipient: ExecutionAddress
    state_root: Bytes32
    receipts_root: Bytes32
    logs_bloom: ByteVector[BYTES_PER_LOGS_BLOOM]
    prev_randao: Bytes32
    block_number: uint64
    gas_limit: uint64
    gas_used: uint64
    timestamp: uint64
    extra_data: ByteList[MAX_EXTRA_DATA_BYTES]
    base_fee_per_gas: uint256
    block_hash: Hash32
    transactions_root: Root
    withdrawals_root: Root
    # [New in Deneb:EIP4844]
    blob_gas_used: uint64
    # [New in Deneb:EIP4844]
    excess_blob_gas: uint64


class LightClientHeader(Container):
    # Beacon block header
    beacon: BeaconBlockHeader
    # Execution payload header corresponding to `beacon.body_root` (from Capella onward)
    execution: ExecutionPayloadHeader
    execution_branch: ExecutionBranch


class LightClientOptimisticUpdate(Container):
    # Header attested to by the sync committee
    attested_header: LightClientHeader
    # Sync committee aggregate signature
    sync_aggregate: SyncAggregate
    # Slot at which the aggregate signature was created (untrusted)
    signature_slot: Slot


class LightClientFinalityUpdate(Container):
    # Header attested to by the sync committee
    attested_header: LightClientHeader
    # Finalized header corresponding to `attested_header.beacon.state_root`
    finalized_header: LightClientHeader
    finality_branch: FinalityBranch
    # Sync committee aggregate signature
    sync_aggregate: SyncAggregate
    # Slot at which the aggregate signature was created (untrusted)
    signature_slot: Slot


class LightClientUpdate(Container):
    # Header attested to by the sync committee
    attested_header: LightClientHeader
    # Next sync committee corresponding to `attested_header.beacon.state_root`
    next_sync_committee: SyncCommittee
    next_sync_committee_branch: NextSyncCommitteeBranch
    # Finalized header corresponding to `attested_header.beacon.state_root`
    finalized_header: LightClientHeader
    finality_branch: FinalityBranch
    # Sync committee aggregate signature
    sync_aggregate: SyncAggregate
    # Slot at which the aggregate signature was created (untrusted)
    signature_slot: Slot


class LightClientBootstrap(Container):
    # Header matching the requested beacon block root
    header: LightClientHeader
    # Current sync committee corresponding to `header.beacon.state_root`
    current_sync_committee: SyncCommittee
    current_sync_committee_branch: CurrentSyncCommitteeBranch


class PowBlock(Container):
    block_hash: Hash32
    parent_hash: Hash32
    total_difficulty: uint256


class Withdrawal(Container):
    index: WithdrawalIndex
    validator_index: ValidatorIndex
    address: ExecutionAddress
    amount: Gwei


class ExecutionPayload(Container):
    parent_hash: Hash32
    fee_recipient: ExecutionAddress
    state_root: Bytes32
    receipts_root: Bytes32
    logs_bloom: ByteVector[BYTES_PER_LOGS_BLOOM]
    prev_randao: Bytes32
    block_number: uint64
    gas_limit: uint64
    gas_used: uint64
    timestamp: uint64
    extra_data: ByteList[MAX_EXTRA_DATA_BYTES]
    base_fee_per_gas: uint256
    block_hash: Hash32
    transactions: List[Transaction, MAX_TRANSACTIONS_PER_PAYLOAD]
    withdrawals: List[Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD]
    # [New in Deneb:EIP4844]
    blob_gas_used: uint64
    # [New in Deneb:EIP4844]
    excess_blob_gas: uint64


class BLSToExecutionChange(Container):
    validator_index: ValidatorIndex
    from_bls_pubkey: BLSPubkey
    to_execution_address: ExecutionAddress


class SignedBLSToExecutionChange(Container):
    message: BLSToExecutionChange
    signature: BLSSignature


class HistoricalSummary(Container):
    block_summary_root: Root
    state_summary_root: Root


class BlobSidecar(Container):
    index: BlobIndex
    blob: Blob
    kzg_commitment: KZGCommitment
    kzg_proof: KZGProof
    signed_block_header: SignedBeaconBlockHeader
    kzg_commitment_inclusion_proof: Vector[
        Bytes32, KZG_COMMITMENT_INCLUSION_PROOF_DEPTH
    ]


class BlobIdentifier(Container):
    block_root: Root
    index: BlobIndex


class PendingDeposit(Container):
    pubkey: BLSPubkey
    withdrawal_credentials: Bytes32
    amount: Gwei
    signature: BLSSignature
    slot: Slot


class PendingPartialWithdrawal(Container):
    validator_index: ValidatorIndex
    amount: Gwei
    withdrawable_epoch: Epoch


class PendingConsolidation(Container):
    source_index: ValidatorIndex
    target_index: ValidatorIndex


class BeaconState(Container):
    genesis_time: uint64  # immutable
    genesis_validators_root: Root  # immutable
    slot: Slot  # `process_slots`
    fork: Fork  # only upgrade functions
    latest_block_header: BeaconBlockHeader  # `process_block_header`
    block_roots: Vector[Root, SLOTS_PER_HISTORICAL_ROOT]  # `process_slot`
    state_roots: Vector[Root, SLOTS_PER_HISTORICAL_ROOT]  # `process_slot`
    historical_roots: List[
        Root, HISTORICAL_ROOTS_LIMIT
    ]  # `process_historical_roots_update`
    eth1_data: Eth1Data  # `process_eth1_data`
    eth1_data_votes: List[
        Eth1Data, EPOCHS_PER_ETH1_VOTING_PERIOD * SLOTS_PER_EPOCH
    ]  # `process_eth1_data`, `process_eth1_data_reset`
    eth1_deposit_index: uint64  # `process_deposit`
    validators: List[
        Validator, VALIDATOR_REGISTRY_LIMIT
    ]  # `add_validator_to_registry`, `slash_validator`, `switch_to_compounding_validator`, `process_bls_to_execution_change`, `process_effective_balance_updates`, `process_registry_updates`, `initiate_validator_exit`
    balances: List[
        Gwei, VALIDATOR_REGISTRY_LIMIT
    ]  # `increase_balance`, `decrease_balance`, `add_validator_to_registry`, `queue_excess_active_balance`
    randao_mixes: Vector[
        Bytes32, EPOCHS_PER_HISTORICAL_VECTOR
    ]  # `process_randao`, `process_randao_mixes_reset`
    slashings: Vector[
        Gwei, EPOCHS_PER_SLASHINGS_VECTOR
    ]  # `slash_validator`, `process_slashings_reset`
    previous_epoch_participation: List[
        ParticipationFlags, VALIDATOR_REGISTRY_LIMIT
    ]  # `add_validator_to_registry`, `process_participation_flag_updates`, `process_attestation`, `translate_participation`
    current_epoch_participation: List[
        ParticipationFlags, VALIDATOR_REGISTRY_LIMIT
    ]  # `add_validator_to_registry`, `process_participation_flag_updates`, `process_attestation`
    justification_bits: Bitvector[
        JUSTIFICATION_BITS_LENGTH
    ]  # `weigh_justification_and_finalization`
    previous_justified_checkpoint: Checkpoint  # `weigh_justification_and_finalization`
    current_justified_checkpoint: Checkpoint  # `weigh_justification_and_finalization`
    finalized_checkpoint: Checkpoint  # `weigh_justification_and_finalization`
    inactivity_scores: List[
        uint64, VALIDATOR_REGISTRY_LIMIT
    ]  # `add_validator_to_registry`, `process_inactivity_updates`
    current_sync_committee: SyncCommittee  # `process_sync_committee_updates`
    next_sync_committee: SyncCommittee  # `process_sync_committee_updates`
    latest_execution_payload_header: (
        ExecutionPayloadHeader  # `process_execution_payload`
    )
    next_withdrawal_index: WithdrawalIndex  # `process_withdrawals`
    next_withdrawal_validator_index: ValidatorIndex  # `process_withdrawals`
    historical_summaries: List[
        HistoricalSummary, HISTORICAL_ROOTS_LIMIT
    ]  # `process_historical_summaries_update`
    # [New in Electra:EIP6110]
    deposit_requests_start_index: uint64  # `process_deposit_request`
    # [New in Electra:EIP7251]
    deposit_balance_to_consume: Gwei  # `process_pending_deposits`
    # [New in Electra:EIP7251]
    exit_balance_to_consume: Gwei  # `compute_exit_epoch_and_update_churn`
    # [New in Electra:EIP7251]
    earliest_exit_epoch: Epoch  # `compute_exit_epoch_and_update_churn`
    # [New in Electra:EIP7251]
    consolidation_balance_to_consume: (
        Gwei  # `compute_consolidation_epoch_and_update_churn`
    )
    # [New in Electra:EIP7251]
    earliest_consolidation_epoch: (
        Epoch  # `compute_consolidation_epoch_and_update_churn`
    )
    # [New in Electra:EIP7251]
    pending_deposits: List[
        PendingDeposit, PENDING_DEPOSITS_LIMIT
    ]  # `apply_deposit`, `process_pending_deposits`, `queue_excess_active_balance`, `process_deposit_request`
    # [New in Electra:EIP7251]
    pending_partial_withdrawals: List[
        PendingPartialWithdrawal, PENDING_PARTIAL_WITHDRAWALS_LIMIT
    ]  # `process_withdrawal_request`, `process_withdrawals`
    # [New in Electra:EIP7251]
    pending_consolidations: List[
        PendingConsolidation, PENDING_CONSOLIDATIONS_LIMIT
    ]  # `process_pending_consolidations`, `process_consolidation_request`


class DepositRequest(Container):
    pubkey: BLSPubkey
    withdrawal_credentials: Bytes32
    amount: Gwei
    signature: BLSSignature
    index: uint64


class WithdrawalRequest(Container):
    source_address: ExecutionAddress
    validator_pubkey: BLSPubkey
    amount: Gwei


class ConsolidationRequest(Container):
    source_address: ExecutionAddress
    source_pubkey: BLSPubkey
    target_pubkey: BLSPubkey


class ExecutionRequests(Container):
    # [New in Electra:EIP6110]
    deposits: List[DepositRequest, MAX_DEPOSIT_REQUESTS_PER_PAYLOAD]
    # [New in Electra:EIP7002:EIP7251]
    withdrawals: List[WithdrawalRequest, MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD]
    # [New in Electra:EIP7251]
    consolidations: List[ConsolidationRequest, MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD]


class BeaconBlockBody(Container):
    randao_reveal: BLSSignature
    eth1_data: Eth1Data
    graffiti: Bytes32
    proposer_slashings: List[ProposerSlashing, MAX_PROPOSER_SLASHINGS]
    # [Modified in Electra:EIP7549]
    attester_slashings: List[AttesterSlashing, MAX_ATTESTER_SLASHINGS_ELECTRA]
    # [Modified in Electra:EIP7549]
    attestations: List[Attestation, MAX_ATTESTATIONS_ELECTRA]
    deposits: List[Deposit, MAX_DEPOSITS]
    voluntary_exits: List[SignedVoluntaryExit, MAX_VOLUNTARY_EXITS]
    sync_aggregate: SyncAggregate
    execution_payload: ExecutionPayload
    bls_to_execution_changes: List[
        SignedBLSToExecutionChange, MAX_BLS_TO_EXECUTION_CHANGES
    ]
    blob_kzg_commitments: List[KZGCommitment, MAX_BLOB_COMMITMENTS_PER_BLOCK]
    # [New in Electra]
    execution_requests: ExecutionRequests


class BeaconBlock(Container):
    slot: Slot
    proposer_index: ValidatorIndex
    parent_root: Root
    state_root: Root
    body: BeaconBlockBody


class SignedBeaconBlock(Container):
    message: BeaconBlock
    signature: BLSSignature


class SingleAttestation(Container):
    committee_index: CommitteeIndex
    attester_index: ValidatorIndex
    data: AttestationData
    signature: BLSSignature


@dataclass(eq=True, frozen=True)
class LatestMessage(object):
    epoch: Epoch
    root: Root


@dataclass
class Store(object):
    time: uint64  # `on_tick_per_slot`
    genesis_time: uint64  # immutable
    justified_checkpoint: Checkpoint  # `update_checkpoints`
    finalized_checkpoint: Checkpoint  # `update_checkpoints`
    unrealized_justified_checkpoint: Checkpoint  # `update_unrealized_checkpoints`
    unrealized_finalized_checkpoint: Checkpoint  # `update_unrealized_checkpoints`
    proposer_boost_root: Root  # `on_tick_per_slot`, `on_block`
    equivocating_indices: Set[ValidatorIndex]  # `on_attester_slashing`
    blocks: Dict[Root, BeaconBlock] = field(default_factory=dict)  # `on_block`
    block_states: Dict[Root, BeaconState] = field(default_factory=dict)  # `on_block`
    block_timeliness: Dict[Root, boolean] = field(default_factory=dict)  # `on_block`
    checkpoint_states: Dict[Checkpoint, BeaconState] = field(
        default_factory=dict
    )  # `store_target_checkpoint_state`
    latest_messages: Dict[ValidatorIndex, LatestMessage] = field(
        default_factory=dict
    )  # `update_latest_messages`
    unrealized_justifications: Dict[Root, Checkpoint] = field(
        default_factory=dict
    )  # `compute_pulled_up_tip`


@dataclass
class LightClientStore(object):
    # Header that is finalized
    finalized_header: LightClientHeader
    # Sync committees corresponding to the finalized header
    current_sync_committee: SyncCommittee
    next_sync_committee: SyncCommittee
    # Best available header to switch finalized head to if we see nothing else
    best_valid_update: Optional[LightClientUpdate]
    # Most recent available reasonably-safe header
    optimistic_header: LightClientHeader
    # Max number of active participants in a sync committee (used to calculate safety threshold)
    previous_max_active_participants: uint64
    current_max_active_participants: uint64


@dataclass
class NewPayloadRequest(object):
    execution_payload: ExecutionPayload
    versioned_hashes: Sequence[VersionedHash]
    parent_beacon_block_root: Root
    # [New in Electra]
    execution_requests: ExecutionRequests


@dataclass
class PayloadAttributes(object):
    timestamp: uint64
    prev_randao: Bytes32
    suggested_fee_recipient: ExecutionAddress
    withdrawals: Sequence[Withdrawal]
    parent_beacon_block_root: Root  # [New in Deneb:EIP4788]


@dataclass
class OptimisticStore(object):
    optimistic_roots: Set[Root]
    head_block_root: Root
    blocks: Dict[Root, BeaconBlock] = field(default_factory=dict)
    block_states: Dict[Root, BeaconState] = field(default_factory=dict)


@dataclass
class BlobsBundle(object):
    commitments: List[KZGCommitment, MAX_BLOB_COMMITMENTS_PER_BLOCK]
    proofs: List[KZGProof, MAX_BLOB_COMMITMENTS_PER_BLOCK]
    blobs: List[Blob, MAX_BLOB_COMMITMENTS_PER_BLOCK]


@dataclass
class GetPayloadResponse(object):
    execution_payload: ExecutionPayload
    block_value: uint256
    blobs_bundle: BlobsBundle
    execution_requests: Sequence[bytes]  # [New in Electra]


class ExecutionEngine(Protocol):
    def notify_new_payload(
        self,
        execution_payload: ExecutionPayload,
        parent_beacon_block_root: Root,
        execution_requests_list: Sequence[bytes],
    ) -> bool:
        """
        Return ``True`` if and only if ``execution_payload`` and ``execution_requests_list``
        are valid with respect to ``self.execution_state``.
        """
        ...

    def is_valid_block_hash(
        self,
        execution_payload: ExecutionPayload,
        parent_beacon_block_root: Root,
        execution_requests_list: Sequence[bytes],
    ) -> bool:
        """
        Return ``True`` if and only if ``execution_payload.block_hash`` is computed correctly.
        """
        ...

    def verify_and_notify_new_payload(
        self, new_payload_request: NewPayloadRequest
    ) -> bool: ...

    def notify_forkchoice_updated(
        self,
        head_block_hash: Hash32,
        safe_block_hash: Hash32,
        finalized_block_hash: Hash32,
        payload_attributes: Optional[PayloadAttributes],
    ) -> Optional[PayloadId]: ...

    def get_payload(self, payload_id: PayloadId) -> GetPayloadResponse:
        """
        Return ExecutionPayload, uint256, BlobsBundle and execution requests (as Sequence[bytes]) objects.
        """
        # pylint: disable=unused-argument
        ...

    def is_valid_versioned_hashes(self, new_payload_request: NewPayloadRequest) -> bool:
        """
        Return ``True`` if and only if the version hashes computed by the blob transactions of
        ``new_payload_request.execution_payload`` matches ``new_payload_request.versioned_hashes``.
        """
        ...


class NoopExecutionEngine(ExecutionEngine):
    def notify_new_payload(
        self: ExecutionEngine,
        execution_payload: ExecutionPayload,
        parent_beacon_block_root: Root,
        execution_requests_list: Sequence[bytes],
    ) -> bool:
        return True

    def notify_forkchoice_updated(
        self: ExecutionEngine,
        head_block_hash: Hash32,
        safe_block_hash: Hash32,
        finalized_block_hash: Hash32,
        payload_attributes: Optional[PayloadAttributes],
    ) -> Optional[PayloadId]:
        pass

    def get_payload(self: ExecutionEngine, payload_id: PayloadId) -> GetPayloadResponse:
        # pylint: disable=unused-argument
        raise NotImplementedError("no default block production")

    def is_valid_block_hash(
        self: ExecutionEngine,
        execution_payload: ExecutionPayload,
        parent_beacon_block_root: Root,
        execution_requests_list: Sequence[bytes],
    ) -> bool:
        return True

    def is_valid_versioned_hashes(
        self: ExecutionEngine, new_payload_request: NewPayloadRequest
    ) -> bool:
        return True

    def verify_and_notify_new_payload(
        self: ExecutionEngine, new_payload_request: NewPayloadRequest
    ) -> bool:
        return True

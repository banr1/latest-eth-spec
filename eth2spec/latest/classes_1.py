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
    Protocol
)

from eth2spec.utils import bls
from eth2spec.utils.ssz.ssz_typing import Bytes8, Bytes20, ByteList, ByteVector
from eth2spec.utils.ssz.ssz_typing import Bitvector  # noqa: F401
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
    Bytes32,
    Bytes48,
    Bytes96,
    Bitlist,
)

from eth2spec.latest.funcs_0 import *
from eth2spec.latest.constants_0 import *
from eth2spec.latest.classes_0 import *
from eth2spec.latest.constants_1 import *

class Transaction(ByteList[MAX_BYTES_PER_TRANSACTION]):
    pass


class Blob(ByteVector[BYTES_PER_FIELD_ELEMENT * FIELD_ELEMENTS_PER_BLOB]):  # type: ignore
    pass


class Configuration(NamedTuple):
    PRESET_BASE: str
    MIN_GENESIS_ACTIVE_VALIDATOR_COUNT: uint64
    MIN_GENESIS_TIME: uint64
    GENESIS_FORK_VERSION: Version
    GENESIS_DELAY: uint64
    SECONDS_PER_SLOT: uint64
    SECONDS_PER_ETH1_BLOCK: uint64
    MIN_VALIDATOR_WITHDRAWABILITY_DELAY: uint64
    SHARD_COMMITTEE_PERIOD: uint64
    ETH1_FOLLOW_DISTANCE: uint64
    EJECTION_BALANCE: Gwei
    MIN_PER_EPOCH_CHURN_LIMIT: uint64
    CHURN_LIMIT_QUOTIENT: uint64
    PROPOSER_SCORE_BOOST: uint64
    REORG_HEAD_WEIGHT_THRESHOLD: uint64
    REORG_PARENT_WEIGHT_THRESHOLD: uint64
    REORG_MAX_EPOCHS_SINCE_FINALIZATION: Epoch
    MAX_PAYLOAD_SIZE: int
    MAX_REQUEST_BLOCKS: int
    EPOCHS_PER_SUBNET_SUBSCRIPTION: int
    MIN_EPOCHS_FOR_BLOCK_REQUESTS: int
    ATTESTATION_PROPAGATION_SLOT_RANGE: int
    MAXIMUM_GOSSIP_CLOCK_DISPARITY: int
    MESSAGE_DOMAIN_INVALID_SNAPPY: DomainType
    MESSAGE_DOMAIN_VALID_SNAPPY: DomainType
    SUBNETS_PER_NODE: int
    ATTESTATION_SUBNET_COUNT: int
    ATTESTATION_SUBNET_EXTRA_BITS: int
    ATTESTATION_SUBNET_PREFIX_BITS: int
    INACTIVITY_SCORE_BIAS: uint64
    INACTIVITY_SCORE_RECOVERY_RATE: uint64
    ALTAIR_FORK_VERSION: Version
    ALTAIR_FORK_EPOCH: Epoch
    TERMINAL_TOTAL_DIFFICULTY: int
    TERMINAL_BLOCK_HASH: Hash32
    TERMINAL_BLOCK_HASH_ACTIVATION_EPOCH: int
    BELLATRIX_FORK_VERSION: Version
    BELLATRIX_FORK_EPOCH: Epoch
    CAPELLA_FORK_VERSION: Version
    CAPELLA_FORK_EPOCH: Epoch
    MAX_BLOBS_PER_BLOCK: uint64
    MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT: uint64
    DENEB_FORK_VERSION: Version
    DENEB_FORK_EPOCH: Epoch
    MAX_REQUEST_BLOCKS_DENEB: int
    MAX_REQUEST_BLOB_SIDECARS: int
    MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS: int
    BLOB_SIDECAR_SUBNET_COUNT: int
    MAX_BLOBS_PER_BLOCK_ELECTRA: uint64
    MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA: Gwei
    MAX_PER_EPOCH_ACTIVATION_EXIT_CHURN_LIMIT: Gwei
    ELECTRA_FORK_VERSION: Version
    ELECTRA_FORK_EPOCH: Epoch
    MAX_REQUEST_BLOB_SIDECARS_ELECTRA: int
    BLOB_SIDECAR_SUBNET_COUNT_ELECTRA: int


config = Configuration(
    PRESET_BASE="mainnet",
    MIN_GENESIS_ACTIVE_VALIDATOR_COUNT=uint64(16384),
    MIN_GENESIS_TIME=uint64(1606824000),
    GENESIS_FORK_VERSION=Version("0x00000000"),
    GENESIS_DELAY=uint64(604800),
    SECONDS_PER_SLOT=uint64(12),
    SECONDS_PER_ETH1_BLOCK=uint64(14),
    MIN_VALIDATOR_WITHDRAWABILITY_DELAY=uint64(256),
    SHARD_COMMITTEE_PERIOD=uint64(256),
    ETH1_FOLLOW_DISTANCE=uint64(2048),
    EJECTION_BALANCE=Gwei(16000000000),
    MIN_PER_EPOCH_CHURN_LIMIT=uint64(4),
    CHURN_LIMIT_QUOTIENT=uint64(65536),
    PROPOSER_SCORE_BOOST=uint64(40),
    REORG_HEAD_WEIGHT_THRESHOLD=uint64(20),
    REORG_PARENT_WEIGHT_THRESHOLD=uint64(160),
    REORG_MAX_EPOCHS_SINCE_FINALIZATION=Epoch(2),
    MAX_PAYLOAD_SIZE=10485760,
    MAX_REQUEST_BLOCKS=1024,
    EPOCHS_PER_SUBNET_SUBSCRIPTION=256,
    MIN_EPOCHS_FOR_BLOCK_REQUESTS=33024,
    ATTESTATION_PROPAGATION_SLOT_RANGE=32,
    MAXIMUM_GOSSIP_CLOCK_DISPARITY=500,
    MESSAGE_DOMAIN_INVALID_SNAPPY=DomainType("0x00000000"),
    MESSAGE_DOMAIN_VALID_SNAPPY=DomainType("0x01000000"),
    SUBNETS_PER_NODE=2,
    ATTESTATION_SUBNET_COUNT=64,
    ATTESTATION_SUBNET_EXTRA_BITS=0,
    ATTESTATION_SUBNET_PREFIX_BITS=int(6),
    INACTIVITY_SCORE_BIAS=uint64(4),
    INACTIVITY_SCORE_RECOVERY_RATE=uint64(16),
    ALTAIR_FORK_VERSION=Version("0x01000000"),
    ALTAIR_FORK_EPOCH=Epoch(74240),
    TERMINAL_TOTAL_DIFFICULTY=58750000000000000000000,
    TERMINAL_BLOCK_HASH=Hash32(
        "0x0000000000000000000000000000000000000000000000000000000000000000"
    ),
    TERMINAL_BLOCK_HASH_ACTIVATION_EPOCH=18446744073709551615,
    BELLATRIX_FORK_VERSION=Version("0x02000000"),
    BELLATRIX_FORK_EPOCH=Epoch(144896),
    CAPELLA_FORK_VERSION=Version("0x03000000"),
    CAPELLA_FORK_EPOCH=Epoch(194048),
    MAX_BLOBS_PER_BLOCK=uint64(6),
    MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT=uint64(8),
    DENEB_FORK_VERSION=Version("0x04000000"),
    DENEB_FORK_EPOCH=Epoch(269568),
    MAX_REQUEST_BLOCKS_DENEB=128,
    MAX_REQUEST_BLOB_SIDECARS=768,
    MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS=4096,
    BLOB_SIDECAR_SUBNET_COUNT=6,
    MAX_BLOBS_PER_BLOCK_ELECTRA=uint64(9),
    MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA=Gwei(128000000000),
    MAX_PER_EPOCH_ACTIVATION_EXIT_CHURN_LIMIT=Gwei(256000000000),
    ELECTRA_FORK_VERSION=Version("0x05000000"),
    ELECTRA_FORK_EPOCH=Epoch(364032),
    MAX_REQUEST_BLOB_SIDECARS_ELECTRA=1152,
    BLOB_SIDECAR_SUBNET_COUNT_ELECTRA=9,
)


class BLSFieldElement(bls.Scalar):
    pass


class Polynomial(list):
    def __init__(self, evals: Optional[Sequence[BLSFieldElement]] = None):
        if evals is None:
            evals = [BLSFieldElement(0)] * FIELD_ELEMENTS_PER_BLOB
        if len(evals) != FIELD_ELEMENTS_PER_BLOB:
            raise ValueError("expected FIELD_ELEMENTS_PER_BLOB evals")
        super().__init__(evals)


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
    genesis_time: uint64
    genesis_validators_root: Root
    slot: Slot
    fork: Fork
    latest_block_header: BeaconBlockHeader
    block_roots: Vector[Root, SLOTS_PER_HISTORICAL_ROOT]
    state_roots: Vector[Root, SLOTS_PER_HISTORICAL_ROOT]
    historical_roots: List[Root, HISTORICAL_ROOTS_LIMIT]
    eth1_data: Eth1Data
    eth1_data_votes: List[Eth1Data, EPOCHS_PER_ETH1_VOTING_PERIOD * SLOTS_PER_EPOCH]
    eth1_deposit_index: uint64
    validators: List[Validator, VALIDATOR_REGISTRY_LIMIT]
    balances: List[Gwei, VALIDATOR_REGISTRY_LIMIT]
    randao_mixes: Vector[Bytes32, EPOCHS_PER_HISTORICAL_VECTOR]
    slashings: Vector[Gwei, EPOCHS_PER_SLASHINGS_VECTOR]
    previous_epoch_participation: List[ParticipationFlags, VALIDATOR_REGISTRY_LIMIT]
    current_epoch_participation: List[ParticipationFlags, VALIDATOR_REGISTRY_LIMIT]
    justification_bits: Bitvector[JUSTIFICATION_BITS_LENGTH]
    previous_justified_checkpoint: Checkpoint
    current_justified_checkpoint: Checkpoint
    finalized_checkpoint: Checkpoint
    inactivity_scores: List[uint64, VALIDATOR_REGISTRY_LIMIT]
    current_sync_committee: SyncCommittee
    next_sync_committee: SyncCommittee
    latest_execution_payload_header: ExecutionPayloadHeader
    next_withdrawal_index: WithdrawalIndex
    next_withdrawal_validator_index: ValidatorIndex
    historical_summaries: List[HistoricalSummary, HISTORICAL_ROOTS_LIMIT]
    # [New in Electra:EIP6110]
    deposit_requests_start_index: uint64
    # [New in Electra:EIP7251]
    deposit_balance_to_consume: Gwei
    # [New in Electra:EIP7251]
    exit_balance_to_consume: Gwei
    # [New in Electra:EIP7251]
    earliest_exit_epoch: Epoch
    # [New in Electra:EIP7251]
    consolidation_balance_to_consume: Gwei
    # [New in Electra:EIP7251]
    earliest_consolidation_epoch: Epoch
    # [New in Electra:EIP7251]
    pending_deposits: List[PendingDeposit, PENDING_DEPOSITS_LIMIT]
    # [New in Electra:EIP7251]
    pending_partial_withdrawals: List[
        PendingPartialWithdrawal, PENDING_PARTIAL_WITHDRAWALS_LIMIT
    ]
    # [New in Electra:EIP7251]
    pending_consolidations: List[PendingConsolidation, PENDING_CONSOLIDATIONS_LIMIT]


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
    time: uint64
    genesis_time: uint64
    justified_checkpoint: Checkpoint
    finalized_checkpoint: Checkpoint
    unrealized_justified_checkpoint: Checkpoint
    unrealized_finalized_checkpoint: Checkpoint
    proposer_boost_root: Root
    equivocating_indices: Set[ValidatorIndex]
    blocks: Dict[Root, BeaconBlock] = field(default_factory=dict)
    block_states: Dict[Root, BeaconState] = field(default_factory=dict)
    block_timeliness: Dict[Root, boolean] = field(default_factory=dict)
    checkpoint_states: Dict[Checkpoint, BeaconState] = field(default_factory=dict)
    latest_messages: Dict[ValidatorIndex, LatestMessage] = field(default_factory=dict)
    unrealized_justifications: Dict[Root, Checkpoint] = field(default_factory=dict)


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

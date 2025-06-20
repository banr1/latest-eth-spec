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


class Slot(uint64):
    pass


class Epoch(uint64):
    pass


class CommitteeIndex(uint64):
    pass


class ValidatorIndex(uint64):
    pass


class Gwei(uint64):
    pass


class Root(Bytes32):
    pass


class Hash32(Bytes32):
    pass


class Version(Bytes4):
    pass


class DomainType(Bytes4):
    pass


class ForkDigest(Bytes4):
    pass


class Domain(Bytes32):
    pass


class BLSPubkey(Bytes48):
    pass


class BLSSignature(Bytes96):
    pass


class NodeID(uint256):
    pass


class SubnetID(uint64):
    pass


class Ether(uint64):
    pass


class ParticipationFlags(uint8):
    pass


class FinalityBranch(Vector[Bytes32, floorlog2(FINALIZED_ROOT_GINDEX_ELECTRA)]):  # type: ignore
    pass


class CurrentSyncCommitteeBranch(
    Vector[Bytes32, floorlog2(CURRENT_SYNC_COMMITTEE_GINDEX_ELECTRA)]
):  # type: ignore
    pass


class NextSyncCommitteeBranch(
    Vector[Bytes32, floorlog2(NEXT_SYNC_COMMITTEE_GINDEX_ELECTRA)]
):  # type: ignore
    pass


class ExecutionAddress(Bytes20):
    pass


class PayloadId(Bytes8):
    pass


class WithdrawalIndex(uint64):
    pass


class ExecutionBranch(Vector[Bytes32, floorlog2(EXECUTION_PAYLOAD_GINDEX)]):  # type: ignore
    pass


class VersionedHash(Bytes32):
    pass


class BlobIndex(uint64):
    pass


class G1Point(Bytes48):
    pass


class G2Point(Bytes96):
    pass


class KZGCommitment(Bytes48):
    pass


class KZGProof(Bytes48):
    pass

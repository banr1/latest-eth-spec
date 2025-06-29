from eth2spec.latest.constants_0 import *
from eth2spec.latest.funcs_0 import *
from eth2spec.latest.classes_0 import *
from eth2spec.latest.constants_1 import *
from eth2spec.latest.classes_1 import *
from eth2spec.latest.funcs_1 import *
from eth2spec.latest.funcs_2 import *
from eth2spec.latest.funcs_2_read_state import *


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

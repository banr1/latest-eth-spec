from eth2spec.latest.constants_0 import *
from eth2spec.latest.funcs_0 import *
from eth2spec.latest.classes_0 import *
from eth2spec.latest.constants_1 import *
from eth2spec.latest.classes_1 import *
from eth2spec.latest.funcs_1 import *
from eth2spec.latest.funcs_2 import *
from eth2spec.latest.funcs_2_read_state import *


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

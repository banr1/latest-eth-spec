from eth2spec.latest.constants_0 import *
from eth2spec.latest.funcs_0 import *
from eth2spec.latest.classes_0 import *
from eth2spec.latest.constants_1 import *
from eth2spec.latest.classes_1 import *
from eth2spec.latest.funcs_1 import *
from eth2spec.latest.funcs_2 import *
from eth2spec.latest.funcs_2_read_state import *


def compute_subscribed_subnets(node_id: NodeID, epoch: Epoch) -> Sequence[SubnetID]:
    return [
        compute_subscribed_subnet(node_id, epoch, index)
        for index in range(config.SUBNETS_PER_NODE)
    ]


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

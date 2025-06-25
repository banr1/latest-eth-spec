from eth2spec.latest.constants_0 import *
from eth2spec.latest.funcs_0 import *
from eth2spec.latest.classes_0 import *
from eth2spec.latest.constants_1 import *
from eth2spec.latest.classes_1 import *
from eth2spec.latest.funcs_1 import *
from eth2spec.latest.funcs_2 import *


def get_block_signature(
    state: BeaconState, block: BeaconBlock, privkey: int
) -> BLSSignature:
    domain = get_domain(
        state, DOMAIN_BEACON_PROPOSER, compute_epoch_at_slot(block.slot)
    )
    signing_root = compute_signing_root(block, domain)
    return bls.Sign(privkey, signing_root)

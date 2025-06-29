from eth2spec.latest.constants_0 import *
from eth2spec.latest.funcs_0 import *
from eth2spec.latest.classes_0 import *
from eth2spec.latest.constants_1 import *
from eth2spec.latest.classes_1 import *
from eth2spec.latest.funcs_1 import *
from eth2spec.latest.funcs_2 import *
from eth2spec.latest.funcs_2_read_state import *


def is_valid_genesis_state(state: BeaconState) -> bool:
    if state.genesis_time < config.MIN_GENESIS_TIME:
        return False
    if (
        len(get_active_validator_indices(state, GENESIS_EPOCH))
        < config.MIN_GENESIS_ACTIVE_VALIDATOR_COUNT
    ):
        return False
    return True

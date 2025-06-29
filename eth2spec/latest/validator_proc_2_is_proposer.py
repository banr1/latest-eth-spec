from eth2spec.latest.constants_0 import *
from eth2spec.latest.funcs_0 import *
from eth2spec.latest.classes_0 import *
from eth2spec.latest.constants_1 import *
from eth2spec.latest.classes_1 import *
from eth2spec.latest.funcs_1 import *
from eth2spec.latest.funcs_2_write_state import *
from eth2spec.latest.funcs_2_read_store import *
from eth2spec.latest.funcs_2_read_state import *


def is_proposer(state: BeaconState, validator_index: ValidatorIndex) -> bool:
    return get_beacon_proposer_index(state) == validator_index

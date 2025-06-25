from eth2spec.latest.constants_0 import *
from eth2spec.latest.funcs_0 import *
from eth2spec.latest.classes_0 import *
from eth2spec.latest.constants_1 import *
from eth2spec.latest.classes_1 import *
from eth2spec.latest.funcs_1 import *
from eth2spec.latest.funcs_2 import *


def check_if_validator_active(
    state: BeaconState, validator_index: ValidatorIndex
) -> bool:
    validator = state.validators[validator_index]
    return is_active_validator(validator, get_current_epoch(state))

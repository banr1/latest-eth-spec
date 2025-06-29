from eth2spec.latest.constants_0 import *
from eth2spec.latest.funcs_0 import *
from eth2spec.latest.classes_0 import *
from eth2spec.latest.constants_1 import *
from eth2spec.latest.classes_1 import *
from eth2spec.latest.funcs_1 import *
from eth2spec.latest.funcs_2 import *
from eth2spec.latest.funcs_2_read_state import *


def get_validator_activation_churn_limit(state: BeaconState) -> uint64:
    """
    Return the validator activation churn limit for the current epoch.
    """
    return min(
        config.MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT, get_validator_churn_limit(state)
    )


def get_validator_churn_limit(state: BeaconState) -> uint64:
    """
    Return the validator churn limit for the current epoch.
    """
    active_validator_indices = get_active_validator_indices(
        state, get_current_epoch(state)
    )
    return max(
        config.MIN_PER_EPOCH_CHURN_LIMIT,
        uint64(len(active_validator_indices)) // config.CHURN_LIMIT_QUOTIENT,
    )

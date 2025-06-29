from eth2spec.latest.constants_0 import *
from eth2spec.latest.funcs_0 import *
from eth2spec.latest.classes_0 import *
from eth2spec.latest.constants_1 import *
from eth2spec.latest.classes_1 import *
from eth2spec.latest.funcs_1 import *
from eth2spec.latest.funcs_2_write_state import *
from eth2spec.latest.funcs_2_read_store import *
from eth2spec.latest.funcs_2_read_state import *
from eth2spec.latest.funcs_3_4_checkpoint import *


def on_tick(store: Store, time: uint64) -> None:
    # If the ``store.time`` falls behind, while loop catches up slot by slot
    # to ensure that every previous slot is processed with ``on_tick_per_slot``
    tick_slot = (time - store.genesis_time) // config.SECONDS_PER_SLOT
    while get_current_slot(store) < tick_slot:
        previous_time = (
            store.genesis_time + (get_current_slot(store) + 1) * config.SECONDS_PER_SLOT
        )
        on_tick_per_slot(store, previous_time)
    on_tick_per_slot(store, time)


def on_tick_per_slot(store: Store, time: uint64) -> None:
    previous_slot = get_current_slot(store)

    # Update store time
    store.time = time

    current_slot = get_current_slot(store)

    # If this is a new slot, reset store.proposer_boost_root
    if current_slot > previous_slot:
        store.proposer_boost_root = Root()

    # If a new epoch, pull-up justification and finalization from previous epoch
    if (
        current_slot > previous_slot
        and compute_slots_since_epoch_start(current_slot) == 0
    ):
        update_checkpoints(
            store,
            store.unrealized_justified_checkpoint,
            store.unrealized_finalized_checkpoint,
        )


def compute_slots_since_epoch_start(slot: Slot) -> int:
    return slot - compute_start_slot_at_epoch(compute_epoch_at_slot(slot))

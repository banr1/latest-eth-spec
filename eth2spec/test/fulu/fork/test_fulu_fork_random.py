from random import Random

from eth2spec.test.context import (
    large_validator_set,
    low_balances,
    misc_balances,
    spec_test,
    with_custom_state,
    with_phases,
    with_presets,
    with_state,
)
from eth2spec.test.helpers.constants import (
    ELECTRA,
    FULU,
    MINIMAL,
)
from eth2spec.test.helpers.fulu.fork import (
    FULU_FORK_TEST_META_TAGS,
    run_fork_test,
)
from eth2spec.test.helpers.random import randomize_state
from eth2spec.test.utils import with_meta_tags


@with_phases(phases=[ELECTRA], other_phases=[FULU])
@spec_test
@with_state
@with_meta_tags(FULU_FORK_TEST_META_TAGS)
def test_fulu_fork_random_0(spec, phases, state):
    randomize_state(spec, state, rng=Random(1010))
    yield from run_fork_test(phases[FULU], state)


@with_phases(phases=[ELECTRA], other_phases=[FULU])
@spec_test
@with_state
@with_meta_tags(FULU_FORK_TEST_META_TAGS)
def test_fulu_fork_random_1(spec, phases, state):
    randomize_state(spec, state, rng=Random(2020))
    yield from run_fork_test(phases[FULU], state)


@with_phases(phases=[ELECTRA], other_phases=[FULU])
@spec_test
@with_state
@with_meta_tags(FULU_FORK_TEST_META_TAGS)
def test_fulu_fork_random_2(spec, phases, state):
    randomize_state(spec, state, rng=Random(3030))
    yield from run_fork_test(phases[FULU], state)


@with_phases(phases=[ELECTRA], other_phases=[FULU])
@spec_test
@with_state
@with_meta_tags(FULU_FORK_TEST_META_TAGS)
def test_fulu_fork_random_3(spec, phases, state):
    randomize_state(spec, state, rng=Random(4040))
    yield from run_fork_test(phases[FULU], state)


@with_phases(phases=[ELECTRA], other_phases=[FULU])
@spec_test
@with_custom_state(
    balances_fn=low_balances, threshold_fn=lambda spec: spec.config.EJECTION_BALANCE
)
@with_meta_tags(FULU_FORK_TEST_META_TAGS)
def test_fulu_fork_random_low_balances(spec, phases, state):
    randomize_state(spec, state, rng=Random(5050))
    yield from run_fork_test(phases[FULU], state)


@with_phases(phases=[ELECTRA], other_phases=[FULU])
@spec_test
@with_custom_state(
    balances_fn=misc_balances, threshold_fn=lambda spec: spec.config.EJECTION_BALANCE
)
@with_meta_tags(FULU_FORK_TEST_META_TAGS)
def test_fulu_fork_random_misc_balances(spec, phases, state):
    randomize_state(spec, state, rng=Random(6060))
    yield from run_fork_test(phases[FULU], state)


@with_phases(phases=[ELECTRA], other_phases=[FULU])
@with_presets(
    [MINIMAL],
    reason="mainnet config leads to larger validator set than limit of public/private keys pre-generated",
)
@spec_test
@with_custom_state(
    balances_fn=large_validator_set,
    threshold_fn=lambda spec: spec.config.EJECTION_BALANCE,
)
@with_meta_tags(FULU_FORK_TEST_META_TAGS)
def test_fulu_fork_random_large_validator_set(spec, phases, state):
    randomize_state(spec, state, rng=Random(7070))
    yield from run_fork_test(phases[FULU], state)

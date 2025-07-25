"""
Ethereum Specification
^^^^^^^^^^^^^^^^^^^^^^

.. contents:: Table of Contents
    :backlinks: none
    :local:

Introduction
------------

Entry point for the Ethereum specification.
"""

from dataclasses import dataclass
from typing import List, Optional, Set, Tuple, Union

from ethereum_rlp import rlp
from ethereum_types.bytes import Bytes
from ethereum_types.numeric import U64, U256, Uint

from ethereum.crypto.hash import Hash32, keccak256
from ethereum.ethash import dataset_size, generate_cache, hashimoto_light
from ethereum.exceptions import (
    EthereumException,
    GasUsedExceedsLimitError,
    InsufficientBalanceError,
    InvalidBlock,
    InvalidSenderError,
    NonceMismatchError,
)

from . import vm
from .blocks import Block, Header, Log, Receipt, encode_receipt
from .bloom import logs_bloom
from .exceptions import (
    InsufficientMaxFeePerGasError,
    PriorityFeeGreaterThanMaxFeeError,
)
from .fork_types import Address
from .state import (
    State,
    account_exists_and_is_empty,
    create_ether,
    destroy_account,
    destroy_touched_empty_accounts,
    get_account,
    increment_nonce,
    set_account_balance,
    state_root,
)
from .transactions import (
    AccessListTransaction,
    FeeMarketTransaction,
    LegacyTransaction,
    Transaction,
    decode_transaction,
    encode_transaction,
    get_transaction_hash,
    recover_sender,
    validate_transaction,
)
from .trie import root, trie_set
from .utils.message import prepare_message
from .vm.interpreter import process_message_call

BLOCK_REWARD = U256(2 * 10**18)
BASE_FEE_MAX_CHANGE_DENOMINATOR = Uint(8)
ELASTICITY_MULTIPLIER = Uint(2)
GAS_LIMIT_ADJUSTMENT_FACTOR = Uint(1024)
GAS_LIMIT_MINIMUM = Uint(5000)
MINIMUM_DIFFICULTY = Uint(131072)
MAX_OMMER_DEPTH = Uint(6)
BOMB_DELAY_BLOCKS = 11400000
EMPTY_OMMER_HASH = keccak256(rlp.encode([]))


@dataclass
class BlockChain:
    """
    History and current state of the block chain.
    """

    blocks: List[Block]
    state: State
    chain_id: U64


def apply_fork(old: BlockChain) -> BlockChain:
    """
    Transforms the state from the previous hard fork (`old`) into the block
    chain object for this hard fork and returns it.

    When forks need to implement an irregular state transition, this function
    is used to handle the irregularity. See the :ref:`DAO Fork <dao-fork>` for
    an example.

    Parameters
    ----------
    old :
        Previous block chain object.

    Returns
    -------
    new : `BlockChain`
        Upgraded block chain object for this hard fork.
    """
    return old


def get_last_256_block_hashes(chain: BlockChain) -> List[Hash32]:
    """
    Obtain the list of hashes of the previous 256 blocks in order of
    increasing block number.

    This function will return less hashes for the first 256 blocks.

    The ``BLOCKHASH`` opcode needs to access the latest hashes on the chain,
    therefore this function retrieves them.

    Parameters
    ----------
    chain :
        History and current state.

    Returns
    -------
    recent_block_hashes : `List[Hash32]`
        Hashes of the recent 256 blocks in order of increasing block number.
    """
    recent_blocks = chain.blocks[-255:]
    # TODO: This function has not been tested rigorously
    if len(recent_blocks) == 0:
        return []

    recent_block_hashes = []

    for block in recent_blocks:
        prev_block_hash = block.header.parent_hash
        recent_block_hashes.append(prev_block_hash)

    # We are computing the hash only for the most recent block and not for
    # the rest of the blocks as they have successors which have the hash of
    # the current block as parent hash.
    most_recent_block_hash = keccak256(rlp.encode(recent_blocks[-1].header))
    recent_block_hashes.append(most_recent_block_hash)

    return recent_block_hashes


def state_transition(chain: BlockChain, block: Block) -> None:
    """
    Attempts to apply a block to an existing block chain.

    All parts of the block's contents need to be verified before being added
    to the chain. Blocks are verified by ensuring that the contents of the
    block make logical sense with the contents of the parent block. The
    information in the block's header must also match the corresponding
    information in the block.

    To implement Ethereum, in theory clients are only required to store the
    most recent 255 blocks of the chain since as far as execution is
    concerned, only those blocks are accessed. Practically, however, clients
    should store more blocks to handle reorgs.

    Parameters
    ----------
    chain :
        History and current state.
    block :
        Block to apply to `chain`.
    """
    validate_header(chain, block.header)
    validate_ommers(block.ommers, block.header, chain)

    block_env = vm.BlockEnvironment(
        chain_id=chain.chain_id,
        state=chain.state,
        block_gas_limit=block.header.gas_limit,
        block_hashes=get_last_256_block_hashes(chain),
        coinbase=block.header.coinbase,
        number=block.header.number,
        base_fee_per_gas=block.header.base_fee_per_gas,
        time=block.header.timestamp,
        difficulty=block.header.difficulty,
    )

    block_output = apply_body(
        block_env=block_env,
        transactions=block.transactions,
        ommers=block.ommers,
    )
    block_state_root = state_root(block_env.state)
    transactions_root = root(block_output.transactions_trie)
    receipt_root = root(block_output.receipts_trie)
    block_logs_bloom = logs_bloom(block_output.block_logs)

    if block_output.block_gas_used != block.header.gas_used:
        raise InvalidBlock(f"{block_output.block_gas_used} != {block.header.gas_used}")
    if transactions_root != block.header.transactions_root:
        raise InvalidBlock
    if block_state_root != block.header.state_root:
        raise InvalidBlock
    if receipt_root != block.header.receipt_root:
        raise InvalidBlock
    if block_logs_bloom != block.header.bloom:
        raise InvalidBlock

    chain.blocks.append(block)
    if len(chain.blocks) > 255:
        # Real clients have to store more blocks to deal with reorgs, but the
        # protocol only requires the last 255
        chain.blocks = chain.blocks[-255:]


def calculate_base_fee_per_gas(
    block_gas_limit: Uint,
    parent_gas_limit: Uint,
    parent_gas_used: Uint,
    parent_base_fee_per_gas: Uint,
) -> Uint:
    """
    Calculates the base fee per gas for the block.

    Parameters
    ----------
    block_gas_limit :
        Gas limit of the block for which the base fee is being calculated.
    parent_gas_limit :
        Gas limit of the parent block.
    parent_gas_used :
        Gas used in the parent block.
    parent_base_fee_per_gas :
        Base fee per gas of the parent block.

    Returns
    -------
    base_fee_per_gas : `Uint`
        Base fee per gas for the block.
    """
    parent_gas_target = parent_gas_limit // ELASTICITY_MULTIPLIER
    if not check_gas_limit(block_gas_limit, parent_gas_limit):
        raise InvalidBlock

    if parent_gas_used == parent_gas_target:
        expected_base_fee_per_gas = parent_base_fee_per_gas
    elif parent_gas_used > parent_gas_target:
        gas_used_delta = parent_gas_used - parent_gas_target

        parent_fee_gas_delta = parent_base_fee_per_gas * gas_used_delta
        target_fee_gas_delta = parent_fee_gas_delta // parent_gas_target

        base_fee_per_gas_delta = max(
            target_fee_gas_delta // BASE_FEE_MAX_CHANGE_DENOMINATOR,
            Uint(1),
        )

        expected_base_fee_per_gas = parent_base_fee_per_gas + base_fee_per_gas_delta
    else:
        gas_used_delta = parent_gas_target - parent_gas_used

        parent_fee_gas_delta = parent_base_fee_per_gas * gas_used_delta
        target_fee_gas_delta = parent_fee_gas_delta // parent_gas_target

        base_fee_per_gas_delta = target_fee_gas_delta // BASE_FEE_MAX_CHANGE_DENOMINATOR

        expected_base_fee_per_gas = parent_base_fee_per_gas - base_fee_per_gas_delta

    return Uint(expected_base_fee_per_gas)


def validate_header(chain: BlockChain, header: Header) -> None:
    """
    Verifies a block header.

    In order to consider a block's header valid, the logic for the
    quantities in the header should match the logic for the block itself.
    For example the header timestamp should be greater than the block's parent
    timestamp because the block was created *after* the parent block.
    Additionally, the block's number should be directly following the parent
    block's number since it is the next block in the sequence.

    Parameters
    ----------
    chain :
        History and current state.
    header :
        Header to check for correctness.
    """
    if header.number < Uint(1):
        raise InvalidBlock
    parent_header_number = header.number - Uint(1)
    first_block_number = chain.blocks[0].header.number
    last_block_number = chain.blocks[-1].header.number

    if (
        parent_header_number < first_block_number
        or parent_header_number > last_block_number
    ):
        raise InvalidBlock

    parent_header = chain.blocks[parent_header_number - first_block_number].header

    if header.gas_used > header.gas_limit:
        raise InvalidBlock

    expected_base_fee_per_gas = calculate_base_fee_per_gas(
        header.gas_limit,
        parent_header.gas_limit,
        parent_header.gas_used,
        parent_header.base_fee_per_gas,
    )
    if expected_base_fee_per_gas != header.base_fee_per_gas:
        raise InvalidBlock

    parent_has_ommers = parent_header.ommers_hash != EMPTY_OMMER_HASH
    if header.timestamp <= parent_header.timestamp:
        raise InvalidBlock
    if header.number != parent_header.number + Uint(1):
        raise InvalidBlock
    if len(header.extra_data) > 32:
        raise InvalidBlock

    block_difficulty = calculate_block_difficulty(
        header.number,
        header.timestamp,
        parent_header.timestamp,
        parent_header.difficulty,
        parent_has_ommers,
    )
    if header.difficulty != block_difficulty:
        raise InvalidBlock

    block_parent_hash = keccak256(rlp.encode(parent_header))
    if header.parent_hash != block_parent_hash:
        raise InvalidBlock

    validate_proof_of_work(header)


def generate_header_hash_for_pow(header: Header) -> Hash32:
    """
    Generate rlp hash of the header which is to be used for Proof-of-Work
    verification.

    In other words, the PoW artefacts `mix_digest` and `nonce` are ignored
    while calculating this hash.

    A particular PoW is valid for a single hash, that hash is computed by
    this function. The `nonce` and `mix_digest` are omitted from this hash
    because they are being changed by miners in their search for a sufficient
    proof-of-work.

    Parameters
    ----------
    header :
        The header object for which the hash is to be generated.

    Returns
    -------
    hash : `Hash32`
        The PoW valid rlp hash of the passed in header.
    """
    header_data_without_pow_artefacts = (
        header.parent_hash,
        header.ommers_hash,
        header.coinbase,
        header.state_root,
        header.transactions_root,
        header.receipt_root,
        header.bloom,
        header.difficulty,
        header.number,
        header.gas_limit,
        header.gas_used,
        header.timestamp,
        header.extra_data,
        header.base_fee_per_gas,
    )

    return keccak256(rlp.encode(header_data_without_pow_artefacts))


def validate_proof_of_work(header: Header) -> None:
    """
    Validates the Proof of Work constraints.

    In order to verify that a miner's proof-of-work is valid for a block, a
    ``mix-digest`` and ``result`` are calculated using the ``hashimoto_light``
    hash function. The mix digest is a hash of the header and the nonce that
    is passed through and it confirms whether or not proof-of-work was done
    on the correct block. The result is the actual hash value of the block.

    Parameters
    ----------
    header :
        Header of interest.
    """
    header_hash = generate_header_hash_for_pow(header)
    # TODO: Memoize this somewhere and read from that data instead of
    # calculating cache for every block validation.
    cache = generate_cache(header.number)
    mix_digest, result = hashimoto_light(
        header_hash, header.nonce, cache, dataset_size(header.number)
    )
    if mix_digest != header.mix_digest:
        raise InvalidBlock

    limit = Uint(U256.MAX_VALUE) + Uint(1)
    if Uint.from_be_bytes(result) > (limit // header.difficulty):
        raise InvalidBlock


def check_transaction(
    block_env: vm.BlockEnvironment,
    block_output: vm.BlockOutput,
    tx: Transaction,
) -> Tuple[Address, Uint]:
    """
    Check if the transaction is includable in the block.

    Parameters
    ----------
    block_env :
        The block scoped environment.
    block_output :
        The block output for the current block.
    tx :
        The transaction.

    Returns
    -------
    sender_address :
        The sender of the transaction.
    effective_gas_price :
        The price to charge for gas when the transaction is executed.

    Raises
    ------
    InvalidBlock :
        If the transaction is not includable.
    GasUsedExceedsLimitError :
        If the gas used by the transaction exceeds the block's gas limit.
    NonceMismatchError :
        If the nonce of the transaction is not equal to the sender's nonce.
    InsufficientBalanceError :
        If the sender's balance is not enough to pay for the transaction.
    InvalidSenderError :
        If the transaction is from an address that does not exist anymore.
    PriorityFeeGreaterThanMaxFeeError:
        If the priority fee is greater than the maximum fee per gas.
    InsufficientMaxFeePerGasError :
        If the maximum fee per gas is insufficient for the transaction.
    """
    gas_available = block_env.block_gas_limit - block_output.block_gas_used
    if tx.gas > gas_available:
        raise GasUsedExceedsLimitError("gas used exceeds limit")
    sender_address = recover_sender(block_env.chain_id, tx)
    sender_account = get_account(block_env.state, sender_address)

    if isinstance(tx, FeeMarketTransaction):
        if tx.max_fee_per_gas < tx.max_priority_fee_per_gas:
            raise PriorityFeeGreaterThanMaxFeeError("priority fee greater than max fee")
        if tx.max_fee_per_gas < block_env.base_fee_per_gas:
            raise InsufficientMaxFeePerGasError(
                tx.max_fee_per_gas, block_env.base_fee_per_gas
            )

        priority_fee_per_gas = min(
            tx.max_priority_fee_per_gas,
            tx.max_fee_per_gas - block_env.base_fee_per_gas,
        )
        effective_gas_price = priority_fee_per_gas + block_env.base_fee_per_gas
        max_gas_fee = tx.gas * tx.max_fee_per_gas
    else:
        if tx.gas_price < block_env.base_fee_per_gas:
            raise InvalidBlock
        effective_gas_price = tx.gas_price
        max_gas_fee = tx.gas * tx.gas_price

    if sender_account.nonce > Uint(tx.nonce):
        raise NonceMismatchError("nonce too low")
    elif sender_account.nonce < Uint(tx.nonce):
        raise NonceMismatchError("nonce too high")
    if Uint(sender_account.balance) < max_gas_fee + Uint(tx.value):
        raise InsufficientBalanceError("insufficient sender balance")
    if sender_account.code:
        raise InvalidSenderError("not EOA")

    return sender_address, effective_gas_price


def make_receipt(
    tx: Transaction,
    error: Optional[EthereumException],
    cumulative_gas_used: Uint,
    logs: Tuple[Log, ...],
) -> Union[Bytes, Receipt]:
    """
    Make the receipt for a transaction that was executed.

    Parameters
    ----------
    tx :
        The executed transaction.
    error :
        Error in the top level frame of the transaction, if any.
    cumulative_gas_used :
        The total gas used so far in the block after the transaction was
        executed.
    logs :
        The logs produced by the transaction.

    Returns
    -------
    receipt :
        The receipt for the transaction.
    """
    receipt = Receipt(
        succeeded=error is None,
        cumulative_gas_used=cumulative_gas_used,
        bloom=logs_bloom(logs),
        logs=logs,
    )

    return encode_receipt(tx, receipt)


def apply_body(
    block_env: vm.BlockEnvironment,
    transactions: Tuple[Union[LegacyTransaction, Bytes], ...],
    ommers: Tuple[Header, ...],
) -> vm.BlockOutput:
    """
    Executes a block.

    Many of the contents of a block are stored in data structures called
    tries. There is a transactions trie which is similar to a ledger of the
    transactions stored in the current block. There is also a receipts trie
    which stores the results of executing a transaction, like the post state
    and gas used. This function creates and executes the block that is to be
    added to the chain.

    Parameters
    ----------
    block_env :
        The block scoped environment.
    transactions :
        Transactions included in the block.
    ommers :
        Headers of ancestor blocks which are not direct parents (formerly
        uncles.)

    Returns
    -------
    block_output :
        The block output for the current block.
    """
    block_output = vm.BlockOutput()

    for i, tx in enumerate(map(decode_transaction, transactions)):
        process_transaction(block_env, block_output, tx, Uint(i))

    pay_rewards(block_env.state, block_env.number, block_env.coinbase, ommers)

    return block_output


def validate_ommers(
    ommers: Tuple[Header, ...], block_header: Header, chain: BlockChain
) -> None:
    """
    Validates the ommers mentioned in the block.

    An ommer block is a block that wasn't canonically added to the
    blockchain because it wasn't validated as fast as the canonical block
    but was mined at the same time.

    To be considered valid, the ommers must adhere to the rules defined in
    the Ethereum protocol. The maximum amount of ommers is 2 per block and
    there cannot be duplicate ommers in a block. Many of the other ommer
    constraints are listed in the in-line comments of this function.

    Parameters
    ----------
    ommers :
        List of ommers mentioned in the current block.
    block_header:
        The header of current block.
    chain :
        History and current state.
    """
    block_hash = keccak256(rlp.encode(block_header))
    if keccak256(rlp.encode(ommers)) != block_header.ommers_hash:
        raise InvalidBlock

    if len(ommers) == 0:
        # Nothing to validate
        return

    # Check that each ommer satisfies the constraints of a header
    for ommer in ommers:
        if Uint(1) > ommer.number or ommer.number >= block_header.number:
            raise InvalidBlock
        validate_header(chain, ommer)
    if len(ommers) > 2:
        raise InvalidBlock

    ommers_hashes = [keccak256(rlp.encode(ommer)) for ommer in ommers]
    if len(ommers_hashes) != len(set(ommers_hashes)):
        raise InvalidBlock

    recent_canonical_blocks = chain.blocks[-(MAX_OMMER_DEPTH + Uint(1)) :]
    recent_canonical_block_hashes = {
        keccak256(rlp.encode(block.header)) for block in recent_canonical_blocks
    }
    recent_ommers_hashes: Set[Hash32] = set()
    for block in recent_canonical_blocks:
        recent_ommers_hashes = recent_ommers_hashes.union(
            {keccak256(rlp.encode(ommer)) for ommer in block.ommers}
        )

    for ommer_index, ommer in enumerate(ommers):
        ommer_hash = ommers_hashes[ommer_index]
        if ommer_hash == block_hash:
            raise InvalidBlock
        if ommer_hash in recent_canonical_block_hashes:
            raise InvalidBlock
        if ommer_hash in recent_ommers_hashes:
            raise InvalidBlock

        # Ommer age with respect to the current block. For example, an age of
        # 1 indicates that the ommer is a sibling of previous block.
        ommer_age = block_header.number - ommer.number
        if Uint(1) > ommer_age or ommer_age > MAX_OMMER_DEPTH:
            raise InvalidBlock
        if ommer.parent_hash not in recent_canonical_block_hashes:
            raise InvalidBlock
        if ommer.parent_hash == block_header.parent_hash:
            raise InvalidBlock


def pay_rewards(
    state: State,
    block_number: Uint,
    coinbase: Address,
    ommers: Tuple[Header, ...],
) -> None:
    """
    Pay rewards to the block miner as well as the ommers miners.

    The miner of the canonical block is rewarded with the predetermined
    block reward, ``BLOCK_REWARD``, plus a variable award based off of the
    number of ommer blocks that were mined around the same time, and included
    in the canonical block's header. An ommer block is a block that wasn't
    added to the canonical blockchain because it wasn't validated as fast as
    the accepted block but was mined at the same time. Although not all blocks
    that are mined are added to the canonical chain, miners are still paid a
    reward for their efforts. This reward is called an ommer reward and is
    calculated based on the number associated with the ommer block that they
    mined.

    Parameters
    ----------
    state :
        Current account state.
    block_number :
        Position of the block within the chain.
    coinbase :
        Address of account which receives block reward and transaction fees.
    ommers :
        List of ommers mentioned in the current block.
    """
    ommer_count = U256(len(ommers))
    miner_reward = BLOCK_REWARD + (ommer_count * (BLOCK_REWARD // U256(32)))
    create_ether(state, coinbase, miner_reward)

    for ommer in ommers:
        # Ommer age with respect to the current block.
        ommer_age = U256(block_number - ommer.number)
        ommer_miner_reward = ((U256(8) - ommer_age) * BLOCK_REWARD) // U256(8)
        create_ether(state, ommer.coinbase, ommer_miner_reward)


def process_transaction(
    block_env: vm.BlockEnvironment,
    block_output: vm.BlockOutput,
    tx: Transaction,
    index: Uint,
) -> None:
    """
    Execute a transaction against the provided environment.

    This function processes the actions needed to execute a transaction.
    It decrements the sender's account after calculating the gas fee and
    refunds them the proper amount after execution. Calling contracts,
    deploying code, and incrementing nonces are all examples of actions that
    happen within this function or from a call made within this function.

    Accounts that are marked for deletion are processed and destroyed after
    execution.

    Parameters
    ----------
    block_env :
        Environment for the Ethereum Virtual Machine.
    block_output :
        The block output for the current block.
    tx :
        Transaction to execute.
    index:
        Index of the transaction in the block.
    """
    trie_set(
        block_output.transactions_trie,
        rlp.encode(index),
        encode_transaction(tx),
    )

    intrinsic_gas = validate_transaction(tx)

    (
        sender,
        effective_gas_price,
    ) = check_transaction(
        block_env=block_env,
        block_output=block_output,
        tx=tx,
    )

    sender_account = get_account(block_env.state, sender)

    effective_gas_fee = tx.gas * effective_gas_price

    gas = tx.gas - intrinsic_gas
    increment_nonce(block_env.state, sender)

    sender_balance_after_gas_fee = Uint(sender_account.balance) - effective_gas_fee
    set_account_balance(block_env.state, sender, U256(sender_balance_after_gas_fee))

    access_list_addresses = set()
    access_list_storage_keys = set()
    if isinstance(tx, (AccessListTransaction, FeeMarketTransaction)):
        for access in tx.access_list:
            access_list_addresses.add(access.account)
            for slot in access.slots:
                access_list_storage_keys.add((access.account, slot))

    tx_env = vm.TransactionEnvironment(
        origin=sender,
        gas_price=effective_gas_price,
        gas=gas,
        access_list_addresses=access_list_addresses,
        access_list_storage_keys=access_list_storage_keys,
        index_in_block=index,
        tx_hash=get_transaction_hash(encode_transaction(tx)),
        traces=[],
    )

    message = prepare_message(block_env, tx_env, tx)

    tx_output = process_message_call(message)

    tx_gas_used_before_refund = tx.gas - tx_output.gas_left
    tx_gas_refund = min(
        tx_gas_used_before_refund // Uint(5), Uint(tx_output.refund_counter)
    )
    tx_gas_used_after_refund = tx_gas_used_before_refund - tx_gas_refund
    tx_gas_left = tx.gas - tx_gas_used_after_refund
    gas_refund_amount = tx_gas_left * effective_gas_price

    # For non-1559 transactions effective_gas_price == tx.gas_price
    priority_fee_per_gas = effective_gas_price - block_env.base_fee_per_gas
    transaction_fee = tx_gas_used_after_refund * priority_fee_per_gas

    # refund gas
    sender_balance_after_refund = get_account(block_env.state, sender).balance + U256(
        gas_refund_amount
    )
    set_account_balance(block_env.state, sender, sender_balance_after_refund)

    # transfer miner fees
    coinbase_balance_after_mining_fee = get_account(
        block_env.state, block_env.coinbase
    ).balance + U256(transaction_fee)
    if coinbase_balance_after_mining_fee != 0:
        set_account_balance(
            block_env.state,
            block_env.coinbase,
            coinbase_balance_after_mining_fee,
        )
    elif account_exists_and_is_empty(block_env.state, block_env.coinbase):
        destroy_account(block_env.state, block_env.coinbase)

    for address in tx_output.accounts_to_delete:
        destroy_account(block_env.state, address)

    destroy_touched_empty_accounts(block_env.state, tx_output.touched_accounts)

    block_output.block_gas_used += tx_gas_used_after_refund

    receipt = make_receipt(
        tx, tx_output.error, block_output.block_gas_used, tx_output.logs
    )

    receipt_key = rlp.encode(Uint(index))
    block_output.receipt_keys += (receipt_key,)

    trie_set(
        block_output.receipts_trie,
        receipt_key,
        receipt,
    )

    block_output.block_logs += tx_output.logs


def check_gas_limit(gas_limit: Uint, parent_gas_limit: Uint) -> bool:
    """
    Validates the gas limit for a block.

    The bounds of the gas limit, ``max_adjustment_delta``, is set as the
    quotient of the parent block's gas limit and the
    ``GAS_LIMIT_ADJUSTMENT_FACTOR``. Therefore, if the gas limit that is
    passed through as a parameter is greater than or equal to the *sum* of
    the parent's gas and the adjustment delta then the limit for gas is too
    high and fails this function's check. Similarly, if the limit is less
    than or equal to the *difference* of the parent's gas and the adjustment
    delta *or* the predefined ``GAS_LIMIT_MINIMUM`` then this function's
    check fails because the gas limit doesn't allow for a sufficient or
    reasonable amount of gas to be used on a block.

    Parameters
    ----------
    gas_limit :
        Gas limit to validate.

    parent_gas_limit :
        Gas limit of the parent block.

    Returns
    -------
    check : `bool`
        True if gas limit constraints are satisfied, False otherwise.
    """
    max_adjustment_delta = parent_gas_limit // GAS_LIMIT_ADJUSTMENT_FACTOR
    if gas_limit >= parent_gas_limit + max_adjustment_delta:
        return False
    if gas_limit <= parent_gas_limit - max_adjustment_delta:
        return False
    if gas_limit < GAS_LIMIT_MINIMUM:
        return False

    return True


def calculate_block_difficulty(
    block_number: Uint,
    block_timestamp: U256,
    parent_timestamp: U256,
    parent_difficulty: Uint,
    parent_has_ommers: bool,
) -> Uint:
    """
    Computes difficulty of a block using its header and parent header.

    The difficulty is determined by the time the block was created after its
    parent. The ``offset`` is calculated using the parent block's difficulty,
    ``parent_difficulty``, and the timestamp between blocks. This offset is
    then added to the parent difficulty and is stored as the ``difficulty``
    variable. If the time between the block and its parent is too short, the
    offset will result in a positive number thus making the sum of
    ``parent_difficulty`` and ``offset`` to be a greater value in order to
    avoid mass forking. But, if the time is long enough, then the offset
    results in a negative value making the block less difficult than
    its parent.

    The base standard for a block's difficulty is the predefined value
    set for the genesis block since it has no parent. So, a block
    can't be less difficult than the genesis block, therefore each block's
    difficulty is set to the maximum value between the calculated
    difficulty and the ``GENESIS_DIFFICULTY``.

    Parameters
    ----------
    block_number :
        Block number of the block.
    block_timestamp :
        Timestamp of the block.
    parent_timestamp :
        Timestamp of the parent block.
    parent_difficulty :
        difficulty of the parent block.
    parent_has_ommers:
        does the parent have ommers.

    Returns
    -------
    difficulty : `ethereum.base_types.Uint`
        Computed difficulty for a block.
    """
    offset = (
        int(parent_difficulty)
        // 2048
        * max(
            (2 if parent_has_ommers else 1)
            - int(block_timestamp - parent_timestamp) // 9,
            -99,
        )
    )
    difficulty = int(parent_difficulty) + offset
    # Historical Note: The difficulty bomb was not present in Ethereum at the
    # start of Frontier, but was added shortly after launch. However since the
    # bomb has no effect prior to block 200000 we pretend it existed from
    # genesis.
    # See https://github.com/ethereum/go-ethereum/pull/1588
    num_bomb_periods = ((int(block_number) - BOMB_DELAY_BLOCKS) // 100000) - 2
    if num_bomb_periods >= 0:
        difficulty += 2**num_bomb_periods

    # Some clients raise the difficulty to `MINIMUM_DIFFICULTY` prior to adding
    # the bomb. This bug does not matter because the difficulty is always much
    # greater than `MINIMUM_DIFFICULTY` on Mainnet.
    return Uint(max(difficulty, int(MINIMUM_DIFFICULTY)))

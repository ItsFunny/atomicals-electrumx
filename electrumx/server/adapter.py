import struct

import electrumx.lib.util
from cbor2 import dumps, loads, CBORDecodeError
from electrumx.lib.util import pack_le_uint64, unpack_le_uint64
from electrumx.lib.hash import double_sha256, hash_to_hex_str

from electrum.bitcoin import script_to_address
from electrum.constants import BitcoinRegtest

# TODO: delete
ACTIVE_HEIGHT = 1


class EntryPoint:
    tx_id: str
    inscription: str
    inscription_context: str

    def __init__(self, tx_id, inscription, inscription_context):
        self.tx_id = tx_id
        self.inscription = inscription
        self.inscription_context = inscription_context


class TransferTrace:
    vin: []
    vout: []


# TODO: optimize?
def get_block_traces(db, height, page, limit):
    key = b'okx' + electrumx.lib.util.pack_le_uint64(height)

    try:
        raw_data = db.read_raw_block(height)
    except FileNotFoundError:
        return None
    version, prev_block_hash, root, ts = parse_block_header(raw_data)
    value = db.utxo_db.get(key)
    if value:
        txs = loads(value)
        len = txs.__len__()
        start = (page - 1) * limit
        end = page * limit
        if end > len:
            end = len
        txs = txs[start:end]
        data = {
            "page": page,
            "block_height": height,
            "sum": len,
            "block_hash": root,
            "prev_block_hash": prev_block_hash,
            "block_time": ts,
            "txs": txs,
        }
        return data
    return None


def parse_block_header(raw_block_data):
    # 区块头长度为 80 字节
    block_header_data = raw_block_data[:80]

    # 解析区块头中的字段
    version = struct.unpack('<I', block_header_data[:4])[0]  # 版本号
    prev_block_hash = block_header_data[4:36].hex()  # 前一区块的哈希值
    merkle_root = block_header_data[36:68].hex()  # Merkle 根
    timestamp = struct.unpack('<I', block_header_data[68:72])[0]  # 时间戳

    return version, prev_block_hash, merkle_root, timestamp


def add_ft_in_trace(ft_transfer_trace_in_cache, tx_hash, prev_hash, input_index, atomicals):
    cache = ft_transfer_trace_in_cache.get(tx_hash)
    node = {
        "input_index": input_index,
        "prev_hash": prev_hash,
        "atomicals": atomicals
    }
    if cache:
        input_index_cache = cache[input_index]
        if input_index_cache:
            # different atomicals
            input_index_cache["atomicals"].append(atomicals)
        else:
            # different input
            cache[input_index] = node
    else:
        ft_transfer_trace_in_cache[tx_hash] = {
            input_index: node
        }


def add_ft_transfer_out_trace(ft_transfer_trace_out_cache, tx_hash, output_index, script, value):
    print(
        f'add transfer out trace,tx_hash:{hash_to_hex_str(tx_hash)},output_index:{output_index},script:{hash_to_hex_str(script)},value:{value}')
    address = get_address_from_script(script)
    cache = ft_transfer_trace_out_cache.get(tx_hash)
    node = {
        "output_index": output_index,
        "address": address,
        "value": value
    }
    if cache:
        cache.append(node)
    else:
        ft_transfer_trace_out_cache[tx_hash] = [node]


def make_point_dict(tx_id, inscription_context):
    return {
        "protocol_name": "arc20",
        "btc_txid": hash_to_hex_str(tx_id),
        "inscription": "",
        "inscription_context": inscription_context
    }


def add_dmt_trace(trace_cache, payload, tx_hash, is_deploy,pubkey_script):
    inscription_context_dict = {
        "is_deploy": is_deploy,
        "address":get_address_from_script(pubkey_script),
        "time": payload["args"]["time"],
        "nonce": payload["args"]["nonce"],
        "bitworkc": payload["args"]["bitworkc"],
        "mint_ticker": payload["args"]["mint_ticker"]
    }
    inscription_context = dumps(inscription_context_dict)
    trace_cache.append(make_point_dict(tx_hash, inscription_context))


def add_ft_trace(trace_cache, operations_found_at_inputs, tx_hash, max_supply,pubkey_script):
    inscription_context_dict = {
        "args": operations_found_at_inputs["args"],
        "address":get_address_from_script(pubkey_script),
        "desc": operations_found_at_inputs["desc"],
        "name": operations_found_at_inputs["name"],
        "image": operations_found_at_inputs["image"],
        "legal": operations_found_at_inputs["legal"],
        "links": operations_found_at_inputs["links"],
        "decimals": operations_found_at_inputs["decimals"],
        "tx_out_value": max_supply,
    }
    inscription_context = dumps(inscription_context_dict)
    trace_cache.append(make_point_dict(tx_hash, inscription_context))


def add_dft_trace(trace_cache, operations_found_at_inputs, tx_hash, is_deploy):
    inscription_context_dict = {
        "is_deploy": is_deploy,
        "args": operations_found_at_inputs["args"],
        "desc": operations_found_at_inputs["desc"],
        "name": operations_found_at_inputs["name"],
        "image": operations_found_at_inputs["image"],
        "legal": operations_found_at_inputs["legal"],
        "links": operations_found_at_inputs["links"],
    }
    inscription_context = dumps(inscription_context_dict)
    trace_cache.append(make_point_dict(tx_hash, inscription_context))


def flush_trace(traces, general_data_cache, height):
    trace_key = b'okx' + pack_le_uint64(height)
    put_general_data = general_data_cache.__setitem__
    data = dumps(traces)
    put_general_data(trace_key, data)
    traces.clear()


def merge_and_clean_trace(traces, ft_transfer_trace_in_cache, ft_transfer_trace_out_cache):
    traces.extend(transfer_merge(ft_transfer_trace_in_cache, ft_transfer_trace_out_cache))
    ft_transfer_trace_in_cache.clear()
    ft_transfer_trace_out_cache.clear()


def transfer_merge(ft_transfer_trace_in_cache, ft_transfer_trace_out_cache):
    ret = []
    for tx_id, out in ft_transfer_trace_out_cache.items():
        trace = TransferTrace()
        inpus = ft_transfer_trace_in_cache.get(tx_id)
        if not inpus:
            raise IndexError(f'not found tx_id:{hash_to_hex_str(tx_id)} in ft_transfer_trace_in_cache')
        trace.vout = out
        trace.vin = inpus
        transfer_trace_dict = {
            "vin": trace.vin,
            "vout": trace.vout
        }
        json_data = dumps(transfer_trace_dict)
        print(f'tx_id:{hash_to_hex_str(tx_id)},trace:{trace}')
        point = {
            "protocol_name": "arc20",
            "btc_txid": hash_to_hex_str(tx_id),
            "inscription": "",
            "inscription_context": json_data
        }
        ret.append(point)
    return ret


def get_address_from_script(script):
    cc = script_to_address(script.hex(), net=BitcoinRegtest)
    print(f'ccccccccccccccccccc {cc}')
    return cc

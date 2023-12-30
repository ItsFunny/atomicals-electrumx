import asyncio
import json
import struct

import electrumx.lib.util
from cbor2 import dumps, loads, CBORDecodeError

from electrumx.lib.script import SCRIPTHASH_LEN
from electrumx.lib.util import pack_le_uint64, unpack_le_uint64
from electrumx.lib.hash import double_sha256, hash_to_hex_str, HASHX_LEN
from electrumx.lib.util_atomicals import location_id_bytes_to_compact, get_address_from_output_script

from electrum.bitcoin import script_to_address
from electrum.constants import BitcoinMainnet

import hashlib


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
        raw_data = asyncio.run(db.raw_header(height))
    except Exception as e:
        return None
    version, prev_block_hash, ts, block_hash = parse_block_header(raw_data)
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
            "count": txs.__len__(),
            "sum": len,
            "block_height": height,
            "block_hash": block_hash,
            "prev_block_hash": prev_block_hash,
            "block_time": ts,
            "txs": txs,
        }
        return data
    return None


def little_endian_to_big_endian(little_endian):
    big_endian = little_endian[::-1]
    return big_endian


def parse_block_header(block_header_data):
    version = struct.unpack('<I', block_header_data[:4])[0]
    prev_block_hash = little_endian_to_big_endian(block_header_data[4:36]).hex()
    timestamp = struct.unpack('<I', block_header_data[68:72])[0]

    sha_hash1 = hashlib.sha256(block_header_data).digest()
    sha256_hash2 = hashlib.sha256(sha_hash1).digest()

    return version, prev_block_hash, timestamp, sha256_hash2[::-1].hex()


def handle_value(value):
    value_sats = value[HASHX_LEN + SCRIPTHASH_LEN: HASHX_LEN + SCRIPTHASH_LEN + 8]
    vv, = unpack_le_uint64(value_sats)
    return vv


def make_point_dict(tx_id, inscription, inscription_context):
    return {
        "protocol_name": "arc-20",
        "inscription": json.dumps(inscription),
        "inscription_context": json.dumps(inscription_context),
        "btc_txid": hash_to_hex_str(tx_id),
        "btc_fee": ""
    }


def add_ft_transfer_trace(trace_cache, tx_hash, tx, atomicals_spent_at_inputs, atomical_id_to_expected_outs_map):
    vin_dict = {}
    for txin_index, atomicals_entry_list in atomicals_spent_at_inputs.items():
        for atomic in atomicals_entry_list:
            atomical_id = atomic["atomical_id"]
            script = atomic["script"]
            value = handle_value(atomic["data"])

            if atomical_id not in vin_dict:
                vin_dict[atomical_id] = {}

            if script not in vin_dict[atomical_id]:
                vin_dict[atomical_id][script] = value
            else:
                vin_dict[atomical_id][script] = vin_dict[atomical_id][script] + value

    flattened_vin = []
    for atomical_id, address_list in vin_dict.items():
        for address, value in address_list.items():
            flattened_vin.append({
                "atomical_id": location_id_bytes_to_compact(atomical_id),
                "address": address,
                "value": value
            })

    vin = []
    for txin_index, atomicals_entry_list in atomicals_spent_at_inputs.items():
        a_list = []
        for atomic in atomicals_entry_list:
            atomical_id = atomic["atomical_id"]
            value = handle_value(atomic["data"])
            a_list.append({
                "atomical_id": location_id_bytes_to_compact(atomical_id),
                "address": atomic["script"],
                "value": value
            })
        vin.append({
            "input_index": txin_index,
            "prev_hash": hash_to_hex_str(tx.inputs[txin_index].prev_hash),
            "atomicals": a_list
        })

    need_vout_index = {}
    for k, v in atomical_id_to_expected_outs_map.items():
        for vv in v:
            need_vout_index[vv] = True

    vout = []
    for idx, txout in enumerate(tx.outputs):
        if idx not in need_vout_index:
            continue
        value = txout.value
        vout.append({
            "output_index": idx,
            "address": get_address_from_script(txout.pk_script),
            "value": value
        })
    trace_cache.append(make_point_dict(tx_hash, {"op": "transfer"}, {
        "tx_id": hash_to_hex_str(tx_hash),
        "flattened_vin": flattened_vin,
        "vin": vin,
        "vout": vout
    }))


def add_dmt_trace(trace_cache, payload, tx_hash, pubkey_script, atomical_id, mint_amount, expected_output_index):
    inscription_context_dict = {
        "address": get_address_from_script(pubkey_script),
        "time": get_from_map(payload["args"], "time"),
        "nonce": get_from_map(payload["args"], "nonce"),
        "bitworkc": get_from_map(payload["args"], "bitworkc"),
        "mint_ticker": payload["args"]["mint_ticker"],
        "mint_amount": mint_amount,
        "atomical_id": location_id_bytes_to_compact(atomical_id),
        "txid": hash_to_hex_str(tx_hash),
        "output_index": expected_output_index,
    }
    trace_cache.append(make_point_dict(tx_hash, {
        "op": "mint"
    }, inscription_context_dict))


def add_ft_trace(trace_cache, operations_found_at_inputs, tx_hash, max_supply, pubkey_script, atomical_id,
                 tx_out_index):
    inscription_context_dict = {
        "time": get_from_map(operations_found_at_inputs["args"],"time"),
        "nonce": get_from_map(operations_found_at_inputs["args"],"nonce"),
        "bitworkc": get_from_map(operations_found_at_inputs["args"],"bitworkc"),
        "request_ticker": get_from_map(operations_found_at_inputs["args"],"request_ticker"),
        "atomical_id": location_id_bytes_to_compact(atomical_id),
        "txid": hash_to_hex_str(tx_hash),
        "output_index": tx_out_index,
        "address": get_address_from_script(pubkey_script),
        "desc": get_from_map(operations_found_at_inputs, "desc"),
        "decimals": get_from_map(operations_found_at_inputs,"decimals"),
        "tx_out_value": max_supply,
    }
    trace_cache.append(make_point_dict(tx_hash, {
        "op": "dmint"
    }, inscription_context_dict))


def get_from_map(m, key):
    if key in m:
        return m[key]
    return ""


def add_dft_trace(trace_cache, operations_found_at_inputs, tx_hash, atomical_id):
    inscription_context_dict = {
        "txid":hash_to_hex_str(tx_hash),
        "time": get_from_map(operations_found_at_inputs["args"],"time"),
        "nonce": get_from_map(operations_found_at_inputs["args"],"nonce"),
        "bitworkc": get_from_map(operations_found_at_inputs["args"],"bitworkc"),
        "max_mints": get_from_map(operations_found_at_inputs["args"],"max_mints"),
        "mint_amount": get_from_map(operations_found_at_inputs["args"],"mint_amount"),
        "mint_height": get_from_map(operations_found_at_inputs["args"],"mint_height"),
        "mint_bitworkc": get_from_map(operations_found_at_inputs["args"],"mint_bitworkc"),
        "request_ticker": get_from_map(operations_found_at_inputs["args"],"request_ticker"),
        "atomical_id": location_id_bytes_to_compact(atomical_id),
        "desc": get_from_map(operations_found_at_inputs, "desc"),
        "name": get_from_map(operations_found_at_inputs, "name"),
    }
    trace_cache.append(make_point_dict(tx_hash, {
        "op": "deploy"
    }, inscription_context_dict))


def flush_trace(traces, general_data_cache, height):
    trace_key = b'okx' + pack_le_uint64(height)
    put_general_data = general_data_cache.__setitem__
    data = dumps(traces)
    put_general_data(trace_key, data)
    if len(data) != 1:
        print(f'scf----- flush_trace {height} {len(traces)}')
    traces.clear()


def get_address_from_script(script):
    return script_to_address(script.hex(), net=BitcoinMainnet)


def get_script_from_by_locatin_id(key, cache, db):
    script = cache.get(key)
    if not script:
        script = db.utxo_db.get(key)
    return get_address_from_script(script)

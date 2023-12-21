import struct

import electrumx.lib.util
from cbor2 import dumps, loads, CBORDecodeError

from electrumx.lib.hash import double_sha256


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
def get_block_traces(db, height):
    prefix = b'okx' + electrumx.lib.util.pack_le_uint64(height)

    raw_data = db.read_raw_block(height)
    version, prev_block_hash, root, ts = parse_block_header(raw_data)
    txs = []
    for db_key, db_value in db.utxo_db.iterator(prefix=prefix):
        point = loads(db_value)
        tx_id = point['tx_id']
        inscription = point['inscription']
        inscription_context = point['inscription_context']
        txs.append({
            "protocol_name": "arc20",
            "inscription": inscription,
            "inscription_context": inscription_context,
            "btc_txid": tx_id
        })
    data = {
        "block_height": height,
        "block_hash": root,
        "prev_block_hash": prev_block_hash,
        "block_time": ts,
        "txs": txs
    }
    return data


def parse_block_header(raw_block_data):
    # 区块头长度为 80 字节
    block_header_data = raw_block_data[:80]

    # 解析区块头中的字段
    version = struct.unpack('<I', block_header_data[:4])[0]  # 版本号
    prev_block_hash = block_header_data[4:36].hex()  # 前一区块的哈希值
    merkle_root = block_header_data[36:68].hex()  # Merkle 根
    timestamp = struct.unpack('<I', block_header_data[68:72])[0]  # 时间戳

    return version, prev_block_hash, merkle_root, timestamp

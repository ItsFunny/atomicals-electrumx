import electrumx.lib.util
from cbor2 import dumps, loads, CBORDecodeError

class EntryPoint:
    tx_id: str
    inscription: str
    inscription_context: str

    def __init__(self,tx_id, inscription, inscription_context):
        self.tx_id=tx_id
        self.inscription = inscription
        self.inscription_context = inscription_context


class TransferTrace:
    vin: []
    vout: []



# TODO: get block all infos
def get_block_traces(db, height):
    prefix = b'okx' + electrumx.lib.util.pack_le_uint64(height)
    for db_key, db_value in db.iterator(prefix=prefix):
        point=loads(db_value)
        tx_id= point['tx_id']
        inscription=point['inscription']
        inscription_context=point['inscription_context']
        print(tx_id, inscription, inscription_context)
    pass

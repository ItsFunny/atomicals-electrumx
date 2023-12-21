
class EntryPoint:
    inscription: str
    inscription_context: str

    def __init__(self,inscription,inscription_context):
        self.inscription=inscription
        self.inscription_context=inscription_context

class TransferTrace:
    tx_id: str
    vin:[]
    vout:[]

    def __init__(self,tx_id):
        self.tx_id=tx_id

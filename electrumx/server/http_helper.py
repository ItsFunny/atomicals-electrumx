import json
import threading

from _cbor2 import dump, dumps
from flask import Flask
from flask import request

from electrumx.server.adapter import get_block_traces
from electrumx.server.db import DB

app = Flask(__name__)


def set_db(db):
    app.db = db


@app.route('/v1/crawler/zeroindexer/<int:height>', methods=['GET'])
def zero_indexer(height):
    print(f'scf zerop_indexer {height}')
    page = request.args.get('page', default=1, type=int)
    limit = request.args.get('limit', default=2147483000, type=int)

    block_data = get_block_traces(app.db, height, page, limit)
    if block_data:
        ret = {
            "code": 0,
            "msg": "success",
            "data": block_data
        }
        ret = json.dumps(ret,ensure_ascii=False)
        return ret
    ret = {
        "code": 1,
        "msg": "block not found",
    }
    ret = json.dumps(ret,ensure_ascii=False)
    return ret


def run_http():
    print("http start,port:36656")
    app.run(debug=False, host="0.0.0.0", port=36656)


def start_http(db):
    set_db(db)
    flask_thread = threading.Thread(target=run_http)
    flask_thread.start()

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


@app.route('/v1/crawler/height/', methods=['GET'])
def height():
    ret = {
        "code": 0,
        "msg": "success",
        "data": {
            "crawler_height":app.db.db_height
        }
    }
    return json.dumps(ret)


@app.route('/v1/crawler/zeroindexer/<int:height>', methods=['GET'])
def zero_indexer(height):
    page = request.args.get('page', default=1, type=int)
    limit = request.args.get('limit', default=2147483000, type=int)

    block_data = get_block_traces(app.db, height, page, limit)
    if block_data:
        ret = {
            "code": 0,
            "msg": "success",
            "data": block_data
        }
        ret = json.dumps(ret)
        return ret
    ret = {
        "code": 1,
        "msg": "block not found",
    }
    ret = json.dumps(ret)
    return ret


def run_http():
    print("http start,port:26656")
    app.run(debug=False, host="0.0.0.0", port=36657)


def start_http(db):
    set_db(db)
    flask_thread = threading.Thread(target=run_http)
    flask_thread.start()
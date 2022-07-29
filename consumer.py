import json
import os
import logging
import time

from flask import Flask
from flask_cors import CORS
from flask import request, jsonify, make_response

import openc2
import kestrelact
from kestrelact import KestrelHuntbookActuator
from oc2 import custom

app = Flask(__name__)
CORS(app)

BASEPATH_V1 = "/v1/openc2"

def _get_requestid(request):
    if 'X-Request-ID' in request.headers:
        return request.headers['X-Request-ID']
    return json.load(request.data)["headers"]["request_id"]

@app.route(BASEPATH_V1, methods=['POST'])
def handle_command():
    d = request.data.decode("utf-8")
    d = json.loads(d)
    app.logger.info(d["body"]["openc2"]["request"])

    act = KestrelHuntbookActuator('investigate.yml')
    cmd = openc2.parse(d["body"]["openc2"]["request"])
    r = act.process(cmd)
    response = {
      "headers": {
          "request_id": _get_requestid(request),
          "created": time.time()
      },
      "body": {
          "openc2": json.loads(r.serialize())
      }
    }
    return make_response(jsonify(response))

if __name__ == '__main__':
    app.run()

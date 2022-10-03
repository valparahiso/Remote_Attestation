from crypt import methods
import ssl
import os
import verifier
import json

from flask import Flask, request

app = Flask(__name__)

cwd = os.getcwd()

CERT_FILE = os.path.join(cwd, '../certs/verifier/verifier.crt')
CA_CERT_FILE = os.path.join(cwd, '../certs/CA/CA.crt')
KEY_FILE = os.path.join(cwd, '../certs/verifier/verifier.key')

ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
ssl_ctx.load_cert_chain(CERT_FILE, KEY_FILE, "verifier")
ssl_ctx.verify_mode = ssl.CERT_REQUIRED
ssl_ctx.load_verify_locations(cafile=CA_CERT_FILE)

@app.route("/node_register", methods=["POST"]) 
def post():
    j = verifier.register_node(json.loads(request.data.decode('UTF-8'))) 
    print(j)
    if "Error" in j.keys():
        return {"Error": j["Error"]}, j["Code"]
    return j

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=6000, debug=True, ssl_context=ssl_ctx)  # TODO togliere il debug mode
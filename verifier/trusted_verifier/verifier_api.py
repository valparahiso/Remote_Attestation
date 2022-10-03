import ssl
import os
import verifier

from flask import Flask

app = Flask(__name__)

cwd = os.getcwd()

CERT_FILE = os.path.join(cwd, './certs/server-cert.pem')
KEY_FILE = os.path.join(cwd, './certs/server-key.pem')

ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
ssl_ctx.load_cert_chain(CERT_FILE, KEY_FILE)
ssl_ctx.verify_mode = ssl.CERT_REQUIRED
ssl_ctx.load_verify_locations(cafile=CERT_FILE)

@app.route("/node_register")
def post():
    j = verifier.register_node()
    print(j)
    if "Error" in j.keys():
        return {"Error": j["Error"]}, j["Code"]
    return j

if __name__ == "__main__":
    app.run(debug=True, ssl_context=ssl_ctx)  # TODO togliere il debug mode
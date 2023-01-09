from crypt import methods
import ssl
import os
import verifier
import datetime

from flask import Flask, request

app = Flask(__name__)

cwd = os.getcwd()

CERT_FILE = os.path.join(cwd, '../certs/verifier/verifier.crt')
CA_CERT_FILE = os.path.join(cwd, '../certs/CA/CA.crt')
KEY_FILE = os.path.join(cwd, '../certs/verifier/verifier.key')

ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
ssl_ctx.load_cert_chain(CERT_FILE, KEY_FILE, "verifier")
 
@app.route("/attest_node", methods=["GET"], endpoint="/attest_node") 
def post():
    now = datetime.datetime.now()
    j = verifier.attest_node(request.args.get('uuid', default = '-1', type = str))  
    print(datetime.datetime.now() - now)
    if "Error" in j.keys():
        return {"Error": j["Error"]}, j["Code"]
    return j

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=7000, debug=True, ssl_context=ssl_ctx)  # TODO togliere il debug mode
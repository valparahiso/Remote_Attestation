import json
from flask import Flask, request
import registrar
from pathlib import Path

context = ('./registrar_cert/myserver.local.crt',
           './registrar_cert/myserver.local.key')

app = Flask(__name__)

@app.route("/platform_providers")
def get():
    j = registrar.get_platform_providers()
    print(j)
    if "Error" in j.keys():
        return {"Error": j["Error"]}, j["Code"]
    return j

@app.route("/provider_register", methods=["POST"]) 
def post():
    j = registrar.register_node(json.loads(request.data.decode('UTF-8')))
    return j


if __name__ == "__main__":
    app.run(debug=True, ssl_context=context)  # TODO togliere il debug mode

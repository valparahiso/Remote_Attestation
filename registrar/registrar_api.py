import json
from flask import Flask, request
import registrar

context = ('../certs/registrar/registrar.crt',
           '../certs/registrar/registrar.key') 

app = Flask(__name__)


@app.route("/platform_providers", methods=["GET"],  endpoint='platform_providers') 
def get():
    j = registrar.get_platform_providers()
    print(j)
    if "Error" in j.keys():
        return {"Error": j["Error"]}, j["Code"]
    return j

@app.route("/provider_register", methods=["POST"],  endpoint='provider_register')
def post():
    j = registrar.register_node(json.loads(request.data.decode('UTF-8')))
    if "Error" in j.keys():
        return {"Error": j["Error"]}, j["Code"]
    return j

@app.route("/provider_accept", methods=["POST"], endpoint='provider_accept')
def post():
    j = registrar.accept_node(json.loads(request.data.decode('UTF-8')))
    if "Error" in j.keys():
        return {"Error": j["Error"]}, j["Code"]
    return j

@app.route("/eapp_register", methods=["POST"],  endpoint='eapp_register')
def post():
    j = registrar.register_eapp(json.loads(request.data.decode('UTF-8')))
    if "Error" in j.keys():
        return {"Error": j["Error"]}, j["Code"] 
    return j

if __name__ == "__main__":
    app.run(debug=True, ssl_context=context)  # TODO togliere il debug mode

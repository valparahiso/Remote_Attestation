from flask import Flask
from flask_restful import Api, Resource

import registrar

app = Flask(__name__)
api = Api(app)

class Platform_Provider(Resource):
    def get(self):
        print(registrar.add(i=1, j=2))
        return {"data":"prova"}

    def post(self):
        return {"data":"Hello World"} 
    

api.add_resource(Platform_Provider, "/platform_providers") 


if __name__ == "__main__":
    app.run(debug=True) #TODO togliere il debug mode

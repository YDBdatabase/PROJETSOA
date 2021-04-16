import json
import bcrypt
import pymongo
from flasgger import Swagger
from flask import Flask, jsonify
from bson import ObjectId
from jsonschema import validate

app = Flask(__name__)
swagger = Swagger(app)

def mongo_connection(mongo_url):
    return pymongo.MongoClient(mongo_url)

def mongo_database_creation(mongo_client, database_name):
    return mongo_client[database_name]

def mongo_collection_creation(database_client, collection_name):
    return database_client[collection_name]

def user_json_validation(dict_to_test):
    with open("./userSchema.json", "r") as fichier:
        dict_schema = json.load(fichier)
    try:
        validate(dict_to_test, dict_schema)
    except Exception as valid_err:
        return [False, valid_err]
    else:
        return [True, "JSON validé"]

class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        return json.JSONEncoder.default(self, o)

mongo_url = "mongodb://localhost:27017/"
mongo_client = mongo_connection(mongo_url)
if mongo_client:
    print("the connection to mongodb was established !")
    database_name = "projectsoa_database"
    database_client = mongo_database_creation(mongo_client, database_name)
    collection_name = "users"
    collection_client = mongo_collection_creation(database_client, collection_name)
    test = collection_client.insert_one({"test": "test"})
    if database_name in mongo_client.list_database_names():
        print("the database was created !")
        if collection_client.count_documents({"test": "test"}) >= 1:
            collection_client.delete_many({"test": "test"})
        ready = True
    else:
        print("the database could not be created...")
        ready = False
else:
    print("the connection to mongodb could not be established...")
    ready = False

@app.route('/colors/<palette>/')
def colors(palette):
    """Example endpoint returning a list of colors by palette
    This is using docstrings for specifications.
    ---
    parameters:
      - name: palette
        in: path
        type: string
        enum: ['all', 'rgb', 'cmyk']
        required: true
        default: all
    definitions:
      Palette:
        type: object
        properties:
          palette_name:
            type: array
            items:
              $ref: '#/definitions/Color'
      Color:
        type: string
    responses:
      200:
        description: A list of colors (may be filtered by palette)
        schema:
          $ref: '#/definitions/Palette'
        examples:
          rgb: ['red', 'green', 'blue']
    """
    all_colors = {
        'cmyk': ['cian', 'magenta', 'yellow', 'black'],
        'rgb': ['red', 'green', 'blue']
    }
    if palette == 'all':
        result = all_colors
    else:
        result = {palette: all_colors.get(palette)}

    return jsonify(result)

@app.route('/users/list/', methods=['GET'])
def list_users():
    return JSONEncoder().encode(list(collection_client.find()))

@app.route('/users/get/<username>/<password>', methods=['GET'])
def get_user(username, password):
    print(str(collection_client.find_one({"username":username,"password":password})))
    return JSONEncoder().encode(collection_client.find_one({"username":username,"password":password}))

@app.route('/api/users/register/', methods=['POST'])
def register_user():
    if request.is_json():
        json = request.json
        if user_json_validation(json)[0]:
            username = json.username
            password = json.password
            if collection_client.find_one({"username":username}) is None:
                print()
            else:
                return Response("The given username already exists...")
        else:
            return Response("The Received Json is not valid...")
    else:
        return Response("No Json Received...")

@app.route('/api/users/connect/', methods=['POST'])
def connect_user():
    if request.is_json():
        json = request.json
        return user_json_validation(json)[1]
    else:
        return Response("No Json Received...", status=406)


if ready: app.run(debug=True)
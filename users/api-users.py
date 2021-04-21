import json
import bson
import bcrypt
import pymongo
from flask_cors import CORS, cross_origin
from flasgger import Swagger
from flask import Flask, Response, jsonify, request
from jsonschema import validate
from bson import json_util

app = Flask(__name__)
swagger = Swagger(app)
CORS(app, support_credentials=True)

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

@app.route('/users/get/<username>', methods=['GET'])
@cross_origin(supports_credentials=True)
def get_user(username):
    """ API function that returns an user with the given username
    ---
    parameters:
      - name: username
        in: path
        required: true
        type: string
    definitions:
      User:
        type: object
        properties:
          _id:
            type: string
          username:
            type: string
          password:
            type: string
    responses:
      200:
        description: An user with the given username
        schema:
          $ref: '#/definitions/User'
    """
    user = collection_client.find_one({"username":username})
    json_user = bson.json_util.dumps(user)
    return Response(json_user, status=200)

@app.route('/users/list', methods=['GET'])
@cross_origin(supports_credentials=True)
def list_users():
    """ API function that returns a list of all users
    ---
    definitions:
      User:
        type: object
        properties:
          _id:
            type: string
          username:
            type: string
          password:
            type: string
    responses:
      200:
        description: A list of all users
        schema:
          type: array
          items:
              $ref: '#/definitions/User'
    """
    users = list(collection_client.find())
    json_users = bson.json_util.dumps(users)
    return Response(json_users, status=200)

@app.route('/users/register', methods=['POST'])
@cross_origin(supports_credentials=True)
def register_user():
    """ API function that registers an user
    ---
    parameters:
      - name: json_user
        in: formData
        required: true
        description: JSON parameters.
    definitions:
      User:
        type: object
        properties:
          username:
            type: string
          password:
            type: string
    consumes:
    - application/json
    responses:
      200:
        description: A success message
      400:
        description: An error message
    """
    if request.is_json and request.json is not None:
        json_user = request.json
        if user_json_validation(json_user)[0]:
            username = json_user["username"]
            password = json_user["password"]
            if collection_client.find_one({"username":username}) is None:
                salt = bcrypt.gensalt()
                password_hash = bcrypt.hashpw(password.encode('utf8'), salt).hex()
                collection_client.insert_one({"username":username,"password":password_hash})
                return Response("The given user is now registered !", status=200)
            else:
                return Response("The given username already exists...", status=400)
        else:
            return Response("The Received Json is not valid...", status=400)
    else:
        return Response("No Json Received...", status=400)

@app.route('/users/connect', methods=['POST'])
@cross_origin(supports_credentials=True)
def connect_user():
    """ API function that connects an user
    ---
    parameters:
      - name: json_user
        in: formData
        required: true
        description: JSON parameters.
    definitions:
      User:
        type: object
        properties:
          username:
            type: string
          password:
            type: string
    consumes:
    - application/json
    responses:
      200:
        description: A success message
      400:
        description: An error message
    """
    if request.is_json and request.json is not None:
        json_user = request.json
        if user_json_validation(json_user)[0]:
            username = json_user["username"]
            password = json_user["password"]
            if collection_client.find_one({"username":username}) is not None:
                stored_user = collection_client.find_one({"username":username})
                if bcrypt.checkpw(password.encode('utf8'), bytes.fromhex(stored_user["password"])):
                    return Response("The given user is connected !", status=200)
                else:
                    return Response("The given password is incorrect...", status=400)
            else:
                return Response("The given username doesn't exists...", status=400)
        else:
            return Response("The Received Json is not valid...", status=400)
    else:
        return Response("No Json Received...", status=400)


if ready: app.run(host='0.0.0.0', port=8000, debug=True)
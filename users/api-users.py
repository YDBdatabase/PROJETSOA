import zmq
import json
import bson
import time
import bcrypt
import pymongo
import calendar
import threading
from flask_cors import CORS, cross_origin
from flasgger import Swagger
from flask import Flask, Response, jsonify, request
from jsonschema import validate
from bson import json_util
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

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

def decrypt(data,key,tag,nonce,enc_session_key):
    # Decrypt the session key with the private RSA key
    cipher_rsa = PKCS1_OAEP.new(key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    # Decrypt the data with the AES session key
    cipher_aes_dec = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes_dec.decrypt_and_verify(data, tag)
    return data.decode("utf-8")

def decryptJWTToken(jwtchiffre):
    f = open('mykey.pem','r')
    key = RSA.import_key(f.read())
    encoded_chiffre_jwt=""
    for i in range(len(jwtchiffre)):
        jwtdechiffre=decrypt(jwtchiffre[i][0],key,jwtchiffre[i][1],jwtchiffre[i][2],jwtchiffre[i][3])
        if(i!=len(jwtchiffre)-1):
            encoded_chiffre_jwt+=str(jwtdechiffre)+"."
        else:
            encoded_chiffre_jwt+=str(jwtdechiffre)

    return encoded_chiffre_jwt

def get_incoming_token():
    recv_socket = context.socket(zmq.PULL)
    recv_socket.connect('tcp://127.0.0.1:5578')
    while True:
        msg = recv_socket.recv_string()
        msgsplited=msg.split("***")
        newmsg=[]
        msgtab=[]
        msgsplit=[]
        for i in range(len(msgsplited)-1):
            msgsplit.append(msgsplited[i].split("^^^"))
        for x in range(len(msgsplit)):
            del msgsplit[x][-1]
        
        for i in range(len(msgsplit)):
            for j in range(len(msgsplit[i])):
                msgsplit[i][j]=msgsplit[i][j].encode('ISO-8859-1')
        encoded_chiffre_jwt=decryptJWTToken(msgsplit)
        return str(encoded_chiffre_jwt)

app = Flask(__name__)
swagger = Swagger(app)
CORS(app, support_credentials=True)

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
                return Response(bson.json_util.dumps({"response":"The given user is now registered !"}), status=200)
            else:
                return Response(bson.json_util.dumps({"response":"The given username already exists..."}), status=400)
        else:
            return Response(bson.json_util.dumps({"response":"The Received Json is not valid..."}), status=400)
    else:
        return Response(bson.json_util.dumps({"response":"No Json Received..."}), status=400)

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
                    datetimestamp=calendar.timegm(time.gmtime())
                    recv_thread = threading.Thread(target=get_incoming_token)
                    recv_thread.start()            
                    message='{"Header":{"alg":"HS256","typ":"JWT"},"Payload":{"iat":"'+str(datetimestamp)+'","Username":"'+username+'"}}'
                    send_socket.send_string(message)
                    token = get_incoming_token()
                    return Response(token, status=200)
                else:
                    return Response(bson.json_util.dumps({"response":"The given password is incorrect..."}), status=400)
            else:
                return Response(bson.json_util.dumps({"response":"The given username doesn\'t exists..."}), status=400)
        else:
            return Response(bson.json_util.dumps({"response":"The Received Json is not valid..."}), status=400)
    else:
        return Response(bson.json_util.dumps({"response":"No Json Received..."}), status=400)

if __name__ == "__main__":
    mongo_url = "mongodb://localhost:27017/"
    mongo_client = mongo_connection(mongo_url)
    try:
        # The ismaster command is cheap and does not require auth.
        mongo_client.admin.command('ismaster')
    except pymongo.errors.ConnectionFailure:
        print("the connection to mongodb could not be established !")
    else:
        print("the connection to mongodb was established !")
        database_name = "projectsoa_database"
        database_client = mongo_database_creation(mongo_client, database_name)
        collection_name = "users"
        collection_client = mongo_collection_creation(database_client, collection_name)
        test = collection_client.insert_one({"test": "test"})
        if database_name in mongo_client.list_database_names():
            print("the database and its collection were created !")
            if collection_client.count_documents({"test": "test"}) >= 1:
                collection_client.delete_many({"test": "test"})
            context = zmq.Context()
            send_socket = context.socket(zmq.PUSH)
            if send_socket is not None:
                send_socket.connect('tcp://127.0.0.1:5579')
                print("the connexion to the token dealer was established !")
                app.run(host='0.0.0.0', port=8000, debug=True)
            else:
                print("the connection to the token dealer could not be established...")
        else:
            print("the database and its collection could not be created...")
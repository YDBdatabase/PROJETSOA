import re
import zmq
import json
import bson
import time
import bcrypt
import pymongo
import calendar
import concurrent.futures
from flask_cors import CORS, cross_origin
from flasgger import Swagger
from flask import Flask, Response, jsonify, request
from jsonschema import validate
from bson import json_util
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

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
        #print(jwtchiffre[i][0],key,jwtchiffre[i][1],jwtchiffre[i][2],jwtchiffre[i][3])
        jwtdechiffre=decrypt(jwtchiffre[i][0],key,jwtchiffre[i][1],jwtchiffre[i][2],jwtchiffre[i][3])
        if(i!=len(jwtchiffre)-1):
            encoded_chiffre_jwt+=str(jwtdechiffre)+"."
        else:
            encoded_chiffre_jwt+=str(jwtdechiffre)

    return encoded_chiffre_jwt

def get_incoming_response():
    recv_socket = context.socket(zmq.PULL)
    recv_socket.connect('tcp://'+jwt_receive_host+':'+jwt_receive_port)
    msg = recv_socket.recv_string()
    return msg

app = Flask(__name__)
swagger = Swagger(app)
CORS(app, support_credentials=True)

@app.route('/apr/get_resource', methods=['GET'])
@cross_origin(supports_credentials=True)
def get_resource():
    """ API function that returns an user with the given username
    ---
    """
    token = request.headers.get('token')
    if token is not None:
        send_socket.send_string(token)
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(get_incoming_response)
            response = future.result()
            print(response)
            return Response("yes", status=200)
    else:
        return Response("no", status=400)

if __name__ == "__main__":
    jwt_send_host = "localhost"
    jwt_send_port = "5556"
    jwt_receive_host = "localhost"
    jwt_receive_port = "5557"
    context = zmq.Context()
    send_socket = context.socket(zmq.PUSH)
    send_socket.connect('tcp://'+jwt_send_host+':'+jwt_send_port)
    app.run(host='localhost', port=5000, debug=True)
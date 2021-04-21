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

def get_incoming_token():
    recv_socket = context.socket(zmq.PULL)
    recv_socket.connect('tcp://127.0.0.1:5578')
    while True:
        msg = recv_socket.recv_string()
        #print(msg)
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

@app.route('/apr/get_resource', methods=['GET'])
@cross_origin(supports_credentials=True)
def get_user(username):
    """ API function that returns an user with the given username
    ---
    """
    return Response("yes", status=200)

if __name__ == "__main__":
    context = zmq.Context()
    send_socket = context.socket(zmq.PUSH)
    if send_socket is not None:
        send_socket.connect('tcp://127.0.0.1:5579')
        print("the connexion to the token dealer was established !")
        app.run(host='localhost', port=5000, debug=True)
    else:
        print("the connection to the token dealer could not be established...")
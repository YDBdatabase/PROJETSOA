import os
from flask.helpers import send_from_directory
import zmq
import concurrent.futures
from flask_cors import CORS, cross_origin
from flasgger import Swagger
from flask import Flask, Response, jsonify, request, send_file
from jsonschema import validate
from bson import json_util
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

def encrypt_data(data):
    
    session_key = get_random_bytes(16)
    recipient_key = RSA.import_key(open("tokenkeypub.pem").read())

    # Encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # Encrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    #print(encoded_jwtsplited[0].encode("utf-8").decode("uf"))
    ciphertext, tag = cipher_aes.encrypt_and_digest(data.encode("utf-8"))
    return ciphertext,tag,cipher_aes.nonce,enc_session_key

def sendJWTToken(token):
    tokensplit=token.split("|")
    #print(encoded_jwt) 
    encoded_jwtsplited=tokensplit[1].split(".")

    #ciphertext,tag,nonce,enc_session_key=encrypt_data(encoded_jwtsplited[0])
    #print(ciphertext)
    #print(decrypt(ciphertext, key, tag, nonce, enc_session_key))

    jwtchiffre=[]
    res,tag,nonce,enc_key=encrypt_data(tokensplit[0])
    jwtchiffre.append([res.decode('ISO-8859-1') ,tag.decode('ISO-8859-1'),nonce.decode('ISO-8859-1'),enc_key.decode('ISO-8859-1')])
    for i in range(len(encoded_jwtsplited)):
        res,tag,nonce,enc_key=encrypt_data(encoded_jwtsplited[i])
        #print(res,tag,nonce,enc_key)
        jwtchiffre.append([res.decode('ISO-8859-1') ,tag.decode('ISO-8859-1'),nonce.decode('ISO-8859-1'),enc_key.decode('ISO-8859-1')])

    return(jwtchiffre) #SEND MESSAGE  

def get_incoming_response():
    recv_socket = context.socket(zmq.PULL)
    recv_socket.connect(os.environ["jWT_ADDRESS_RECEIVE"])
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
        sendJWTToken(token)
        msgToken=sendJWTToken(token)
        messagesplit=""
        for i in range(len(msgToken)):
            msginter=""
            for j in range(len(msgToken[i])):
                msginter+=str(msgToken[i][j])+"^^^"
            messagesplit+=str(msginter)+"***"
        send_socket.send_string(messagesplit)
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(get_incoming_response)
            response = future.result()
            print(response)
            if response == "True": 
                filename = 'secret.png'
                return send_file(filename, mimetype='image/png')
            elif response == "False": return Response("", status=200)

    else:
        return Response("no", status=400)

if __name__ == "__main__":
    jwt_send_host = "localhost"
    jwt_send_port = "5556"
    jwt_receive_host = "localhost"
    jwt_receive_port = "5557"
    context = zmq.Context()
    send_socket = context.socket(zmq.PUSH)
    send_socket.connect(os.environ["jWT_ADDRESS_SEND"])
    app.run(host='0.0.0.0', port=5000, debug=True)
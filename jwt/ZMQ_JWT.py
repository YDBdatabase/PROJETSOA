import jwt
import time
import zmq
import json
from io import StringIO
import threading
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
"""
key = RSA.generate(2048)
f = open('mykey.pem','wb')
f.write(key.export_key('PEM'))
f.close()
"""


def encrypt_data(data):
    
    session_key = get_random_bytes(16)
    recipient_key = RSA.import_key(open("receiver.pem").read())
    # Encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # Encrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    #print(encoded_jwtsplited[0].encode("utf-8").decode("uf"))
    ciphertext, tag = cipher_aes.encrypt_and_digest(data.encode("utf-8"))
    return ciphertext,tag,cipher_aes.nonce,enc_session_key

def sendJWTToken(secret):
    encoded_jwt = jwt.encode(secret, 'aogkrejgi2GA651g5&4dgth6781zlhafi12gri93p3uDNCe', algorithm='HS256')
    #print(encoded_jwt) 
    encoded_jwtsplited=encoded_jwt.split(".")

    ciphertext,tag,nonce,enc_session_key=encrypt_data(encoded_jwtsplited[0])
    #print(ciphertext)
    #print(decrypt(ciphertext, key, tag, nonce, enc_session_key))

    jwtchiffre=[]

    for i in range(len(encoded_jwtsplited)):
        res,tag,nonce,enc_key=encrypt_data(encoded_jwtsplited[i])
        #print(res,tag,nonce,enc_key)
        jwtchiffre.append([res.decode('ISO-8859-1') ,tag.decode('ISO-8859-1'),nonce.decode('ISO-8859-1'),enc_key.decode('ISO-8859-1')])

    return(jwtchiffre) #SEND MESSAGE    


context = zmq.Context()
send_socket = context.socket(zmq.PUSH)
send_socket.bind('tcp://*:5578')

recv_socket = context.socket(zmq.PULL)
recv_socket.bind('tcp://*:5579')
while True:
    msg = recv_socket.recv_string()
    print(f'Message from client: {msg}')
    msgToken = sendJWTToken(json.loads(msg))#{'some': 'payload'}
    messagesplit=""
    for i in range(len(msgToken)):
        msginter=""
        for j in range(len(msgToken[i])):
            msginter+=str(msgToken[i][j])+"^^^"
        messagesplit+=str(msginter)+"***"
    print("Sending...")
    send_socket.send_string(str(messagesplit))

    


    #Decode JWT Token
    """encoded_chiffre_jwt=decryptJWTToken(msgsplit)
    jwtrest=jwt.decode(encoded_chiffre_jwt, 'aogkrejgi2GA651g5&4dgth6781zlhafi12gri93p3uDNCe', algorithms=['HS256'])
    print("jwt= ",jwtrest)"""
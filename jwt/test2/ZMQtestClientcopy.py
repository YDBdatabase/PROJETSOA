import zmq
import threading
import os
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

address = os.environ["ZMQ_ADDRESS"]
address2=os.environ["ZMQ_ADDRESS_2"]
context = zmq.Context()
send_socket = context.socket(zmq.PUSH)
send_socket.connect(address)

def print_incoming_messages():
    recv_socket = context.socket(zmq.PULL)
    recv_socket.connect(address2)
    while True:
        msg = recv_socket.recv_string()
        print(msg)

recv_thread = threading.Thread(target=print_incoming_messages)
recv_thread.start()
msgToken=sendJWTToken('Thaleko|eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJIZWFkZXIiOnsiYWxnIjoiSFMyNTYiLCJ0eXAiOiJKV1QifSwiUGF5bG9hZCI6eyJpYXQiOiIxOTg5ODg5MDgwOCIsIlVzZXJuYW1lIjoiVGhhbGVrbyJ9fQ.ARQxQaXnY5MplyJTlYhD1Z2KIiev4oyHtGsjK1WkRR8')
messagesplit=""
for i in range(len(msgToken)):
    msginter=""
    for j in range(len(msgToken[i])):
        msginter+=str(msgToken[i][j])+"^^^"
    messagesplit+=str(msginter)+"***"
#print(messagesplit)  
send_socket.send_string(messagesplit)

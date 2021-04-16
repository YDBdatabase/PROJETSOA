import jwt
import time
import zmq
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
f = open('mykey.pem','r')
key = RSA.import_key(f.read())
"""
public_key = key.publickey().export_key()
file_out = open("receiver.pem", "wb")
file_out.write(public_key)
file_out.close()

context = zmq.Context()
send_socket = context.socket(zmq.PUSH)
send_socket.bind('tcp://*:5556')

def print_incoming_messages():
    recv_socket = context.socket(zmq.PULL)
    recv_socket.bind('tcp://*:5557')
    while True:
        msg = recv_socket.recv_string()
        print(f'Message from client: {msg}')

# Print incoming messages in background
recv_thread = threading.Thread(target=print_incoming_messages)
recv_thread.start()

while True:
    msg = input('Message to send: ')
    send_socket.send_string(msg)
"""
encoded_jwt = jwt.encode({'some': 'payload'}, 'aogkrejgi2GA651g5&4dgth6781zlhafi12gri93p3uDNCe', algorithm='HS256')
#print(encoded_jwt) 
encoded_jwtsplited=encoded_jwt.split(".")

def encrypt_data(data):
    
    session_key = get_random_bytes(16)

    # Encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # Encrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    #print(encoded_jwtsplited[0].encode("utf-8").decode("uf"))
    ciphertext, tag = cipher_aes.encrypt_and_digest(data.encode("utf-8"))
    return ciphertext,tag,cipher_aes.nonce,enc_session_key

ciphertext,tag,nonce,enc_session_key=encrypt_data(encoded_jwtsplited[0])

def decrypt(data,key,tag,nonce,enc_session_key):
    # Decrypt the session key with the private RSA key
    recipient_key = RSA.import_key(open("receiver.pem").read())
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    # Decrypt the data with the AES session key
    cipher_aes_dec = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes_dec.decrypt_and_verify(data, tag)
    return data.decode("utf-8")

for jwtencoded in encoded_jwtsplited:
    print(jwtencoded)
    jwtchiffre,tag,nonce,enc_session_key=encrypt_data(jwtencoded)
    print(jwtchiffre)
    print(decrypt(jwtchiffre,key,tag,nonce,enc_session_key))
jwt=jwt.decode(encoded_jwt, 'aogkrejgi2GA651g5&4dgth6781zlhafi12gri93p3uDNCe', algorithms=['HS256'])

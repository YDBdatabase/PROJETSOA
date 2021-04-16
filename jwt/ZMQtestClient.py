import zmq
import threading
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

context = zmq.Context()
send_socket = context.socket(zmq.PUSH)
send_socket.connect('tcp://127.0.0.1:5557')

def print_incoming_messages():
    recv_socket = context.socket(zmq.PULL)
    recv_socket.connect('tcp://127.0.0.1:5556')
    while True:
        msg = recv_socket.recv_string()
        print(f'Message from server: {msg}')

recv_thread = threading.Thread(target=print_incoming_messages)
recv_thread.start()

while True:
    msg = input('Message to send: ')
    send_socket.send_string(msg)

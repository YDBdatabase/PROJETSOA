import zmq
import threading
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP


context = zmq.Context()
send_socket = context.socket(zmq.PUSH)
send_socket.connect('tcp://0.0.0.0:3001')

def print_incoming_messages():
    recv_socket = context.socket(zmq.PULL)
    recv_socket.connect('tcp://0.0.0.0:3002')
    while True:
        msg = recv_socket.recv_string()
        print(msg)

recv_thread = threading.Thread(target=print_incoming_messages)
recv_thread.start()

while True:
    msg = input('Message to send: ')
    send_socket.send_string(msg)

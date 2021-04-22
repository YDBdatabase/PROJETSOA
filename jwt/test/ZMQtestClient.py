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


context = zmq.Context()
send_socket = context.socket(zmq.PUSH)
send_socket.connect('tcp://0.0.0.0:5556')

def print_incoming_messages():
    recv_socket = context.socket(zmq.PULL)
    recv_socket.connect('tcp://0.0.0.0:5555')
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
        print("\n",encoded_chiffre_jwt)
        


recv_thread = threading.Thread(target=print_incoming_messages)
recv_thread.start()

"""while True:
    msg = input('Message to send: ')
    send_socket.send_string(msg)"""
print("yes")
send_socket.send_string('{"Header":{"alg":"HS256","typ":"JWT"},"Payload":{"iat":"19898890808","Username":"bigest"}}')
print("done")
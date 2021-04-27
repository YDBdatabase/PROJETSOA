import jwt
import time
import zmq
import json
import os
from io import StringIO
import sys
import threading
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

"""Génération des clés privés et publiques utilisées dans l'entièreté de l'application pour transmettre le jeton JWT"""
"""key = RSA.generate(2048)
private_key = key.export_key()
file_out = open("tokenkeypriv.pem", "wb")
file_out.write(private_key)
file_out.close()

public_key = key.publickey().export_key()
file_out = open("tokenkeypub.pem", "wb")
file_out.write(public_key)
file_out.close()
"""
"""Chiffrement des données via la clé publique"""
def encrypt_data(data):
    
    session_key = get_random_bytes(16)
    try:
        recipient_key = RSA.import_key(open("receiver.pem").read())
    except:
        print("public key not accesible")
    # Encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # Encrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    #print(encoded_jwtsplited[0].encode("utf-8").decode("uf"))
    ciphertext, tag = cipher_aes.encrypt_and_digest(data.encode("utf-8"))
    return ciphertext,tag,cipher_aes.nonce,enc_session_key

"""Déchiffrement des données"""
def decrypt(data,key,tag,nonce,enc_session_key):
    # Decrypt the session key with the private RSA key
    cipher_rsa = PKCS1_OAEP.new(key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    # Decrypt the data with the AES session key
    cipher_aes_dec = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes_dec.decrypt_and_verify(data, tag)
    return data.decode("utf-8")

"""Envoi du JWT Token chiffré par la clé publique"""
def sendJWTToken(secret):               #aogkrejgi2GA651g5&4dgth6781zlhafi12gri93p3uDNCe correspond à l
    encoded_jwt = jwt.encode(secret, 'aogkrejgi2GA651g5&4dgth6781zlhafi12gri93p3uDNCe', algorithm='HS256') #Création du Jeton JWT depuis un secret  | Exemple de secret : '{"Header":{"alg":"HS256","typ":"JWT"},"Payload":{"iat":"19898890808","Username":"Pseudo"}'
    encoded_jwtsplited=encoded_jwt.split(".") #On split afin de chiffré les informations du jeton séparement | Exemple de jeton JWT avant le split : eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJIZWFkZXIiOnsiYWxnIjoiSFMyNTYiLCJ0eXAiOiJKV1QifSwiUGF5bG9hZCI6eyJpYXQiOiIxOTg5ODg5MDgwOCIsIlVzZXJuYW1lIjoiYmlnZXN0In19.qcWo5HSH8x45oqB9736oPujfhLLEQb4bbKOSMvIUXig

    jwtchiffre=[]

    for i in range(len(encoded_jwtsplited)):
        res,tag,nonce,enc_key=encrypt_data(encoded_jwtsplited[i])
        #print(res,tag,nonce,enc_key)
        jwtchiffre.append([res.decode('ISO-8859-1') ,tag.decode('ISO-8859-1'),nonce.decode('ISO-8859-1'),enc_key.decode('ISO-8859-1')]) #On ajoute les données nécessaires pour déchiffrer si on possède la clé privé

    return(jwtchiffre) #Return le jeton JWT chiffré en plusieurs morceaux qu'on peut transmettre avec ZMQ 

"""Retourne le secret du JWT Token"""
def decodeJWTTOKEN(Token):
    jwtrest=jwt.decode(Token, 'aogkrejgi2GA651g5&4dgth6781zlhafi12gri93p3uDNCe', algorithms=['HS256'])
    print("jwt= ",jwtrest)
    return jwtrest

"""Retourne le JWT token déchiffré"""
def decryptJWTToken(jwtchiffre): 
    
    encoded_chiffre_jwt=""
    for i in range(len(jwtchiffre)):
        #print(jwtchiffre[i][0],key,jwtchiffre[i][1],jwtchiffre[i][2],jwtchiffre[i][3])
        jwtdechiffre=decrypt(jwtchiffre[i][0],key,jwtchiffre[i][1],jwtchiffre[i][2],jwtchiffre[i][3])
        if(i!=len(jwtchiffre)-1):
            encoded_chiffre_jwt+=str(jwtdechiffre)+"."
        else:
            encoded_chiffre_jwt+=str(jwtdechiffre)

    return encoded_chiffre_jwt

f = open('tokenkeypriv.pem','r') #Récupération de la clé privée
key = RSA.import_key(f.read())

print("Starting ...")
context = zmq.Context()
address = os.environ["ZMQ_ADDRESS"]
address2=os.environ["ZMQ_ADDRESS_2"]   #Définition des adresses pour ZMQ
address3=os.environ["ZMQ_ADDRESS_3"]
#print(address,address2)
send_socket = context.socket(zmq.PUSH) #Canal d'écriture ZMQ
send_socket.bind(address2)

recv_socket = context.socket(zmq.PULL) #Canal d'écoute ZMQ
recv_socket.bind(address)

send_socketAPR = context.socket(zmq.PUSH) #Canal d'écriture ZMQ
send_socketAPR.bind(address3)
print("Connexion done")
while True:
    msg = recv_socket.recv_string()
    #print(msg)
    if(msg[0]=="{"): #Réception d'un secret 
        try:
            print(f'Message from client: {msg}')
            msgToken = sendJWTToken(json.loads(msg))#Génération d'un JWT Token depuis le message
            messagesplit=""
            for i in range(len(msgToken)):
                msginter=""
                for j in range(len(msgToken[i])):
                    msginter+=str(msgToken[i][j])+"^^^"
                messagesplit+=str(msginter)+"***"
            print("Sending...")
            send_socket.send_string(str(messagesplit)) #Envoi du JWT Token chiffré
        except:
            print("Error while creating JWT TOKEN")
    else: #Réception d'un token JWT chiffré à verifier
        try:
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
            encoded_chiffre_jwt=decryptJWTToken(msgsplit) #Déchiffrement
            #print("encoded : ",encoded_chiffre_jwt)

            msgsplit=encoded_chiffre_jwt.split(".")
            decodeJWT=decodeJWTTOKEN(msgsplit[1]+"."+msgsplit[2]+"."+msgsplit[3])
            #print(decodeJWT,msgsplit[0])
            if(msgsplit[0]==decodeJWT["Payload"]["Username"] and decodeJWT["Header"]["alg"]=="HS256" and decodeJWT["Header"]["typ"]=="JWT"): #Vérification du jeton JWT 
                send_socketAPR.send_string("True") #On retourne True s'il est correcte
            else:
                send_socketAPR.send_string("False")
        except:                                 #On retourne False s'il n'est pas conforme
            send_socketAPR.send_string("False")

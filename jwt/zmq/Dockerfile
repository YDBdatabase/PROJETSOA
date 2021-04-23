FROM python:3

ADD ZMQ_JWT.py /
ADD receiver.pem /
ADD tokenkeypriv.pem /


RUN pip install PyJWT

RUN pip install pycryptodome

RUN pip install ZMQ

CMD [ "python", "./ZMQ_JWT.py" ]


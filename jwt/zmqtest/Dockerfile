FROM python:3

ADD ZMQtestClient.py /
ADD mykey.pem /
RUN pip install PyJWT

RUN pip install pycryptodome

RUN pip install ZMQ

CMD [ "python", "./ZMQtestClient.py" ]


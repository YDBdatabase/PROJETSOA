FROM python:3

ADD ZMQtestClientcopy.py /

RUN pip install PyJWT

RUN pip install pycryptodome

RUN pip install ZMQ

CMD [ "python","-u","ZMQtestClientcopy.py" ]


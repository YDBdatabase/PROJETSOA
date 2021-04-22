FROM python:3

ADD ZMQtestClientcopy.py /

RUN pip install PyJWT

RUN pip install pycryptodome

RUN pip install ZMQ

EXPOSE 5556
EXPOSE 5557
CMD [ "python","-u","ZMQtestClientcopy.py" ]




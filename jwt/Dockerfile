FROM python:3

ADD ZMQ_JWT.py /

RUN pip install PyJWT

RUN pip install pycryptodome

RUN pip install ZMQ

EXPOSE 3001

CMD [ "python","-u","ZMQ_JWT.py" ]


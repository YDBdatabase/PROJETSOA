FROM python:3

ADD ZMQ_JWT.py /

RUN pip install PyJWT

RUN pip install pycryptodome

RUN pip install ZMQ

RUN apt-get update && \
  apt-get install -y --no-install-recommends \
  gcc

CMD [ "python","-u","ZMQ_JWT.py", ]


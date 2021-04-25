FROM python:3
WORKDIR /app
COPY requirements.txt api-apr.py .
RUN pip3 install -r requirements.txt
CMD [ "python", "api-apr.py"]
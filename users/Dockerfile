FROM python:3
WORKDIR /app
COPY api-users.py userSchema.json mykey.pem requirements.txt ./
RUN pip3 install -r requirements.txt
CMD [ "python", "api-users.py"]
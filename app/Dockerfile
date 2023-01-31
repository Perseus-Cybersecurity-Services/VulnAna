FROM python:3.8-slim-buster

WORKDIR /app

COPY ./requirements.txt requirements.txt
COPY app/main/ main/
RUN pip3 install -r requirements.txt

EXPOSE 5000
ENV TZ=Europe/Madrid

CMD gunicorn --bind 0.0.0.0:5000 "main:create_app('prod')"

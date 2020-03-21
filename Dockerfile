FROM python:3.8

WORKDIR /usr/src/app

COPY . .
RUN pip install --no-cache-dir -r ./requirements.txt
RUN python3 build_config.py

RUN mkdir -p /opt/flask-app/static/tracefiles
RUN mkdir -p /opt/flask-app/migrations

RUN DEBIAN_FRONTEND=noninteractive apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y tshark


CMD [ "flask", "run" ]
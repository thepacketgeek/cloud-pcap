#!/bin/bash

docker-compose up --build -d

docker-compose run app flask db init
docker-compose run app flask db migrate -m "initialize"
docker-compose run app flask db upgrade

docker-compose run app flask create-admin
#!/usr/bin/env python3
 

class Config:
    SQLALCHEMY_COMMIT_ON_TEARDOWN = True
    SECRET_KEY = "826df6b2a85731e677d72c2c47c61e3946cfe5c7beaefad90e9be89781ea1d8a"
    SQLALCHEMY_DATABASE_URI = "postgresql://postgres:postgrespswd@db:5432/cloud_pcap"

import os

basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
	SQLALCHEMY_COMMIT_ON_TEARDOWN = True
	SECRET_KEY = '8UsJdJRYm6EhzbdW'

class ProductionConfig(Config):
    pass
    
class DevelopmentConfig(Config):
	SQLALCHEMY_DATABASE_URI = 'postgresql://localhost/cloud-pcap'

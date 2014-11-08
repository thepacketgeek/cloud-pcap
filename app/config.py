import os

basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
	SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'db.sqlite')
	SQLALCHEMY_COMMIT_ON_TEARDOWN = True
	SECRET_KEY = '8UsJdJRYm6EhzbdW'

config = Config
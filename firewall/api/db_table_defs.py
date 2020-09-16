import os
import sqlalchemy_utils
from sqlalchemy import Column
from sqlalchemy import create_engine
from sqlalchemy import types
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker


address = os.environ['POSTGRES_ADDRESS']
database = os.environ['POSTGRES_DB']
user = os.environ['POSTGRES_USER']
password = os.environ['POSTGRES_PASSWORD']

sql_base = declarative_base()

class DBIPAddresses(sql_base):
	__tablename__ = 'iptable'
	ip = Column(types.String, primary_key=True, unique=False)



def get_session_maker():
	engine = create_engine(f'postgresql://{user}:{password}@{address}/{database}')
	if not sqlalchemy_utils.database_exists(engine.url):
		sqlalchemy_utils.create_database(engine.url)
	sql_base.metadata.create_all(engine)
	session_maker = sessionmaker(bind=engine)
	print('connected to database')
	return session_maker

import os
import sqlalchemy_utils
from sqlalchemy import Sequence, Column, Integer, String, create_engine, types
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker


POSTGRES_ADDRESS   = os.environ['POSTGRES_ADDRESS']
POSTGRES_DATABASE  = os.environ['POSTGRES_DATABASE']
POSTGRES_TABLE_IP  = os.environ['POSTGRES_TABLE_IP']
POSTGRES_TABLE_DNS = os.environ['POSTGRES_TABLE_DNS']
POSTGRES_USER      = os.environ['POSTGRES_USER']
POSTGRES_PASSWORD  = os.environ['POSTGRES_PASSWORD']

sql_base = declarative_base()

__session = None

class RuleIP(sql_base):
    __tablename__ = POSTGRES_TABLE_IP
    
    id      = Column(Integer, Sequence('ip_rule_id'), primary_key=True)
    type    = Column(String)
    name    = Column(String)
    trusted = Column(String)
    ip      = Column(String)

    def set_value(self, rule_value):
        ip = rule_value

    def serialize(self):
        return {
            'id':      self.id,
            'type':    self.type,
            'name':    self.name,
            'trusted': self.trusted,
            'ip':      self.ip
        }

class RuleDNS(sql_base):
    __tablename__ = POSTGRES_TABLE_DNS
    
    id      = Column(Integer, Sequence('dns_rule_id'), primary_key=True)
    type    = Column(String)
    name    = Column(String)
    trusted = Column(String)
    dns     = Column(String)

    def set_value(self, rule_value):
        dns = rule_value

    def serialize(self):
        return {
            'id':      self.id,
            'type':    self.type,
            'name':    self.name,
            'trusted': self.trusted,
            'dns':     self.dns
        }


def get_session():
    
    global __session

    if __session == None:
        engine = create_engine(f'postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}@{POSTGRES_ADDRESS}/{POSTGRES_DATABASE}')
        
        if not sqlalchemy_utils.database_exists(engine.url):
            sqlalchemy_utils.create_database(engine.url)
        
        sql_base.metadata.create_all(engine)
        session_maker = sessionmaker(bind=engine)
        __session = session_maker()

    return __session

import flask
import logging

from flask import json
from db_table_defs import DBIPAddresses
from db_table_defs import get_session_maker
from sqlalchemy.exc import IntegrityError

app = flask.Flask(__name__)


gunicorn_logger = logging.getLogger('gunicorn.error')
app.logger.handlers = gunicorn_logger.handlers
app.logger.setLevel(gunicorn_logger.level)


@app.route('/killroute/<ip_address>', methods=['PUT','DELETE'])
def killroute(ip_address):

	method = flask.request.method
	app.logger.debug('%s killroute(%s)', method, ip_address)
	
	if method == 'PUT':

		if route_exists(ip_address):
			app.logger.debug('%s route %s already exists.', method, ip_address)
			return flask.Response(status=200)
		else:
			return write(ip_address)

	elif method == 'DELETE':
		
		return delete(ip_address)


def route_exists(ip_address):
	try:
	
		session_maker = get_session_maker()
		session = session_maker()
		ipquery = session.query(DBIPAddresses)
		query_ip = ipquery.get({"ip":ip_address})
		
		return query_ip != None

	except Exception as exc:

		app.logger.error('Error reading from DB: %s', exc)
		raise exc



@app.route('/getallroutes', methods=['GET'])
def getallroutes():
	
	try:
		
		session_maker = get_session_maker()
		session = session_maker()
		ipquery = session.query(DBIPAddresses)
		query_ips = ipquery.all()

		ip_list = []
		for ip_obj in query_ips:
			ip_list.append(ip_obj.ip)
		
		response_json = {
			'allroutes' : ip_list
		}

		return json.jsonify(response_json)

	except Exception as exc:
		
		app.logger.error('Error reading from DB: %s', exc)
		raise exc


def write(ip_address):
	app.logger.debug('write(%s)', ip_address)
	
	try:
		
		session_maker = get_session_maker()
		session = session_maker()
		ipentry = DBIPAddresses(ip=ip_address)
		session.add(ipentry)
		session.commit()

		return flask.Response(status=200)

	except (IntegrityError, Exception) as exc:
		app.logger.error('Error writing to DB: %s', exc)
		raise exc


def delete(ip_address):
	app.logger.debug('delete(%s)', ip_address)
	
	try:
		
		session_maker = get_session_maker()
		session = session_maker()
		ipquery = session.query(DBIPAddresses)
		ipentry = ipquery.get({"ip":ip_address})
		session.delete(ipentry)
		session.commit()

		return flask.Response(status=200)

	except Exception as exc:
		app.logger.error('Error writing to DB: %s', exc)
		raise exc

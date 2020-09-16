import flask
import logging
import ipaddress

from flask import json
from db_table_defs import DBIPAddresses
from db_table_defs import get_session_maker
from sqlalchemy.exc import IntegrityError

app = flask.Flask(__name__)


gunicorn_logger = logging.getLogger('gunicorn.error')
app.logger.handlers = gunicorn_logger.handlers
app.logger.setLevel(gunicorn_logger.level)


@app.route('/killroute/<ip>', methods=['PUT','DELETE'])
def killroute(ip):

	method = flask.request.method
	app.logger.debug('%s killroute(%s)', method, ip)
	
	try:
		ipaddress.ip_address(ip)
	except ValueError as exc:
		app.logger.error('%s is not a valid IP address', ip)
		raise exc


	if method == 'PUT':
		
		if route_exists(ip):
			app.logger.debug('%s route %s already exists.', method, ip)
			return flask.Response(status=200)
		else:
			return write(ip)

	elif method == 'DELETE':

		if route_exists(ip):
			return delete(ip)
		else:
			app.logger.debug('%s route %s does not exist.', method, ip)
			return flask.Response(status=200)


def route_exists(ip):
	try:
	
		session_maker = get_session_maker()
		session = session_maker()
		ipquery = session.query(DBIPAddresses)
		query_ip = ipquery.get({"ip":ip})
		
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


def write(ip):
	app.logger.debug('write(%s)', ip)
	
	try:
		
		session_maker = get_session_maker()
		session = session_maker()
		ipentry = DBIPAddresses(ip=ip)
		session.add(ipentry)
		session.commit()

		return flask.Response(status=200)

	except (IntegrityError, Exception) as exc:
		app.logger.error('Error writing to DB: %s', exc)
		raise exc


def delete(ip):
	app.logger.debug('delete(%s)', ip)
	
	try:
		
		session_maker = get_session_maker()
		session = session_maker()
		ipquery = session.query(DBIPAddresses)
		ipentry = ipquery.get({"ip":ip})
		session.delete(ipentry)
		session.commit()

		return flask.Response(status=200)

	except Exception as exc:
		app.logger.error('Error writing to DB: %s', exc)
		raise exc

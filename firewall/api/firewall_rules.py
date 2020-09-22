import flask
import logging
import ipaddress

from flask import json
from sqlalchemy.exc import IntegrityError

from firewall_constants import Keyword, Action
from firewall_rule_response import RuleResponse, RuleException
from firewall_table_defs import RuleIP, RuleDNS, get_session
from json_bad_request import JSONBadRequest


gunicorn_logger = logging.getLogger('gunicorn.error')

app = flask.Flask(__name__)
app.logger.handlers = gunicorn_logger.handlers
app.logger.setLevel(gunicorn_logger.level)

_session = None

@app.route('/rules', methods=['POST'])
def rules():
    """
    CRUD endpoint which processes JSON firewall rule requests.
    """

    global _session
    _session = get_session()
    rule_response = None

    try:
        json = _get_request_json()
        action = json[Keyword.ACTION]
        rules = None
        
        if action == Action.READ:
            rules = _read_existing_rules(json[Keyword.TYPE])
        else:
            rules  = json[Keyword.RULES]
            for rule_json in rules:
                _process_rule_json(action, rule_json)
            
        rule_response = RuleResponse(status=200, name='Request Successful', body=rules)
        _session.commit()

    except RuleException as e:
        rule_response = e
        _session.rollback()
        
    _session.close()
    return rule_response.generate_response()

def _get_request_json():
    try:    
        return flask.request.get_json()
    except JSONBadRequest as e:
        raise RuleException(status=400, name='JSON Error', error=e.get_body())


def _process_rule_json(action, rule_json):
    """
    Routes actions to corresponding methods for existing rules.
    """

    if action == Action.CREATE:
        
        if not _check_rule_exists(rule_json):
            rule_instance = _create_new_rule(rule_json)
            rule_json[Keyword.ID] = rule_instance.id

    elif action == Action.UPDATE:
        _update_existing_rule(rule_json)
    elif action == Action.DELETE:
        _delete_rule(rule_json)
    else:
        error_description = f"\'{action}\' is not valid."
        raise RuleException(status=400, name='Unhandled Action', error=error_description)


def _get_rule_class(rule_type):
    """
    Returns a class based on rule type
    """

    if rule_type == Keyword.IP:    
        return RuleIP
    elif rule_type == Keyword.DNS:
        return RuleDNS
    else:
        error_description = f"\'{rule_type}\' is not valid."
        raise RuleException(status=400, name='Unhandled Rule Type', error=error_description)


def _get_rule_instance(rule_json):
    """
    Creates and returns an instance of a rule class initialized with rule parameters.
    """

    rule_type     = rule_json[Keyword.TYPE]
    rule_class    = _get_rule_class(rule_type)
    rule_name     = rule_json[Keyword.NAME]
    rule_value    = rule_json[rule_type]
    rule_trusted  = rule_json[Keyword.TRUSTED]
    rule_instance = rule_class(type=rule_type, name=rule_name, trusted=rule_trusted)
    rule_instance.set_value(rule_value)
    return rule_instance


def _create_new_rule(rule_json):
    """
    Writes a new rule to the corresponding table based on the '__tablename__' property of rule_class.
    """

    rule_instance = _get_rule_instance(rule_json)
    try:
        _session.add(rule_instance)
        return rule_instance
    except (IntegrityError, Exception) as e:
        raise RuleException(status=500, name='Rule Create Error', error=str(e))

def _check_rule_exists(rule_json):
    """
    Checks for the existence of a rule basd on the value of the rule.
    """
    
    rule_type  = rule_json[Keyword.TYPE]
    rule_value = rule_json[rule_type]
    rule_class = _get_rule_class(rule_type)

    if rule_type == Keyword.IP:
        query = _session.query(rule_class).filter(rule_class.ip == rule_value)
    elif rule_type == Keyword.DNS:
        query = _session.query(rule_class).filter(rule_class.dns == rule_value)

    if _session.query(query.exists()).scalar():
        error_description = "One or more rules in request already already exists."
        raise RuleException(status=400, name='Rule Already Exists', error=error_description)

    return False


def _get_existing_rule(rule_json):
    """
    Queries the database for a rule based on provided 'id' property in the rule JSON.
    """

    rule_type  = rule_json[Keyword.TYPE]
    rule_id    = rule_json[Keyword.ID]
    rule_class = _get_rule_class(rule_type)
    try:
        query = _session.query(rule_class)
        return query.get(rule_id)
    except Exception as e:
        raise RuleException(status=500, name='Rule Query Error', error=str(e))


def _read_existing_rules(rule_type):
    """
    Queries the database for all rows in a table based on the '__tablename__' property of the rule_class.
    """

    rule_class = _get_rule_class(rule_type)
    try:
        query = _session.query(rule_class)
        rules_list = query.all()
        return [rule.serialize() for rule in rules_list]
    except Exception as e:
        raise RuleException(status=500, name='Rule Query Error', error=str(e))


def _update_existing_rule(rule_json):
    """
    Modifies the 'name' and 'trusted' fields of a rule stored in the database.
    """

    rule_instance = _get_existing_rule(rule_json)
    if rule_instance != None:
        try:
            rule_instance.name    = rule_json[Keyword.NAME]
            rule_instance.trusted = rule_json[Keyword.TRUSTED]
        except (IntegrityError, Exception) as e:
            raise RuleException(status=500, name='Rule Update Error', error=str(e))
    else:
        error_description = 'Attempt to update rule with invalid id.'
        raise RuleException(status=400, name='Rule Does Not Exist', error=error_description)


def _delete_rule(rule_json):
    """
    Deletes a rule from a table, if it exists.
    """

    rule_instance = _get_existing_rule(rule_json)
    if rule_instance != None:
        try:
            _session.delete(rule_instance)
        except Exception as e:
            raise RuleException(status=500, name='Rule Delete Error', error=str(e))
    else:
        error_description = 'Attempt to delete rule with invalid id'
        raise RuleException(status=400, name='Rule Does Not Exist', error=error_description)


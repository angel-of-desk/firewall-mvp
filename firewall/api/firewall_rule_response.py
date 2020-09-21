import flask

class RuleResponse():
    def __init__(self, status, name, body=None, error=None):
        self.status = status
        self.name   = name
        self.body   = body
        self.error  = error

    def generate_response(self):
        response_json = {
            'status': self.status,
            'name'  : self.name,
            'body'  : self.body,
            'error' : self.error
        }

        return flask.json.jsonify(response_json), self.status


class RuleException(RuleResponse, Exception):
    def __init__(self, status, name, error):
        RuleResponse.__init__(self, status, name, None, error)
        Exception.__init__(self)
        flask.current_app.logger.error('Request had an error: %s', error)

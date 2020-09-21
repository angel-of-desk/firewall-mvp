from werkzeug.exceptions import BadRequest

class JSONBadRequest(BadRequest):
    def get_body(self):
        return {
            'code': self.code,
            'name': self.name,
            'description': self.description
        }

FROM debian:buster
RUN apt-get update \
 && apt-get install --yes --no-install-recommends \
 	  build-essential \
 	  libpq-dev \
      python3 \
      python3-pip \
      python3-dev \
      python3-setuptools \
      python3-wheel \
 && rm -rf /var/lib/apt/lists/* \
 && pip3 install \
 	  gunicorn \
 	  flask \
      psycopg2 \
      sqlalchemy \
      sqlalchemy-utils

ENV FLASK_APP=firewall_rules.py

COPY firewall_rules.py .
COPY firewall_table_defs.py .
COPY firewall_rule_response.py .
COPY firewall_constants.py .
COPY json_bad_request.py .

ENTRYPOINT [ "gunicorn", "firewall_rules:app", "--bind", "0.0.0.0:5000"]

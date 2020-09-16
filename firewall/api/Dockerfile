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

ENV FLASK_APP=api.py

COPY api.py .
COPY db_table_defs.py .

ENTRYPOINT [ "gunicorn", "api:app", "--bind", "0.0.0.0:5000"]

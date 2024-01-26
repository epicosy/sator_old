FROM python:3.10

WORKDIR /opt/sator
COPY . /opt/sator

# dependencies
RUN apt-get update
RUN pip install .
RUN ./setup.sh

ENTRYPOINT sator run -u $SQLALCHEMY_DATABASE_URI -p $PORT

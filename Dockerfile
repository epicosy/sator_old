FROM python:3.10

WORKDIR /opt/sator
COPY . /opt/sator


RUN pip install .
RUN ./setup.sh

ENTRYPOINT sator run -a 0.0.0.0 -p $PORT -u $SQLALCHEMY_DATABASE_URI

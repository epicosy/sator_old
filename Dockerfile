FROM python:3.10

WORKDIR /opt
RUN git clone https://github.com/epicosy/sator.git

WORKDIR /opt/sator
RUN pip install .
RUN ./setup.sh
#RUN sator nvd

ARG DATABASE_URI
ARG PORT
ENV db_uri=$DATABASE_URI

ENTRYPOINT sator run -u ${db_uri} -p $PORT

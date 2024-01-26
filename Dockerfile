FROM python:3.10

ARG PORT
ARG DATABASE_URI
ENV DATABASE_URI=${DATABASE_URI}
EXPOSE 5432

WORKDIR /opt
RUN git clone https://github.com/epicosy/sator.git

WORKDIR /opt/sator
RUN pip install .
RUN ./setup.sh


ENTRYPOINT sator run -u $DATABASE_URI -p $PORT

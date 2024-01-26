FROM python:3.10

ARG PORT
ENV DATABASE_URI=${DATABASE_URI}

WORKDIR /opt
RUN git clone https://github.com/epicosy/sator.git

WORKDIR /opt/sator
RUN pip install .
RUN ./setup.sh


ENTRYPOINT sator run -u $DATABASE_URI -p $PORT

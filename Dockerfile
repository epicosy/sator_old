FROM python:3.10

WORKDIR /opt
RUN git clone https://github.com/epicosy/sator.git

WORKDIR /opt/sator
RUN pip install . & ./setup.sh
RUN sator nvd


ENTRYPOINT ["sator", "run"]

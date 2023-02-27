# Sator: a vulnerability database API

## Installation

```
$ pip install -r requirements.txt

$ python setup.py install
```

### Setting up database

```sh
$ docker run --name sator_db -e POSTGRES_PASSWORD=user123 -e POSTGRES_USER=user1 -e POSTGRES_DB=sator -d -p 5432:5432 postgres
```

### Running server 

```sh
$ sator run [-h] [-p PORT] [-a ADDRESS]
```

## Development

This project includes a number of helpers in the `Makefile` to streamline common development tasks.

### Environment Setup

The following demonstrates setting up and working with a development environment:

```
### create a virtualenv for development

$ make virtualenv

$ source env/bin/activate


### run sator cli application

$ sator --help


### run pytest / coverage

$ make test
```


### Releasing to PyPi

Before releasing to PyPi, you must configure your login credentials:

**~/.pypirc**:

```
[pypi]
username = YOUR_USERNAME
password = YOUR_PASSWORD
```

Then use the included helper function via the `Makefile`:

```
$ make dist

$ make dist-upload
```

## Deployments

### Docker

Included is a basic `Dockerfile` for building and distributing `vulnerability database`,
and can be built with the included `make` helper:

```
$ make docker

$ docker run -it sator --help
```

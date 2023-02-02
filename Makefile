.PHONY: clean virtualenv test docker dist dist-upload

clean:
	find . -name '*.py[co]' -delete

virtualenv:
	virtualenv --prompt '|> sator <|' env
	@echo
	@echo "VirtualENV Setup Complete. Now run: source env/bin/activate"
	@echo

install:
	pip install .[test]

test:
	python -m pytest \
		-v \
		--cov=sator \
		--cov-report=term \
		--cov-report=html:coverage-report \
		tests/

docker: clean
	docker build -t sator:latest .

dist: clean
	rm -rf dist/*
	python setup.py sdist
	python setup.py bdist_wheel

dist-upload:
	twine upload dist/*

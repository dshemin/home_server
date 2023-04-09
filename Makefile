VENV = venv
VENV_BIN = $(VENV)/bin

PIP := $(VENV_BIN)/pip3
ANSIBLE_PLAYBOOK := $(VENV_BIN)/ansible-playbook
ANSIBLE_GALAXY := $(VENV_BIN)/ansible-galaxy
ANSIBLE_LINT := $(VENV_BIN)/ansible-lint
PRE_COMMIT := $(VENV_BIN)/pre-commit

.PHONY: run/testing
run/testing:
	$(ANSIBLE_PLAYBOOK) -i inventory/testing --extra-vars "env=testing" master.yml

.PHONY: lint
lint:
	$(PRE_COMMIT) run --all-files

#
# Install all required dependencies.
#
deps: $(VENV_BIN)/activate
	$(PIP) install -r requirements.txt
	$(PRE_COMMIT) install
	$(ANSIBLE_GALAXY) collection install -r requirements.yaml

#
# Setup virtual environment for python.
#
$(VENV_BIN)/activate:
	virtualenv $(VENV)

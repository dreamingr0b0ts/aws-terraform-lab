# aws-terraform-lab — developer tasks
#
#   make install      install dev + runtime deps
#   make test         run the pytest suite
#   make lint         ruff lint
#   make compile      byte-compile all tool modules
#   make tf-validate  terraform fmt -check + validate (requires terraform)
#   make tf-lint      tflint (if installed)
#   make check        lint + compile + test (+ tf-validate if terraform present)

PY ?= python3

# Tool entry-point modules. Add new tools here as they are implemented.
TOOLS := \
	sg-auditor/sg_auditor.py \
	imds-inspector/imds_inspector.py \
	right-sizer/right_sizer.py \
	ebs-hygiene/ebs_hygiene.py \
	resilience-checker/resilience_checker.py \
	network-reachability/network_reachability.py \
	tf-plan-guard/tf_plan_guard.py

.PHONY: install test lint compile tf-validate tf-lint check

install:
	$(PY) -m pip install -r requirements-dev.txt

test:
	$(PY) -m pytest -q

lint:
	$(PY) -m ruff check .

compile:
	$(PY) -m py_compile $(TOOLS)

tf-validate:
	cd terraform && terraform fmt -check -recursive && terraform init -backend=false && terraform validate

tf-lint:
	cd terraform && tflint --recursive

check: lint compile test
	@command -v terraform >/dev/null 2>&1 && $(MAKE) tf-validate || echo "terraform not installed; skipping tf-validate"

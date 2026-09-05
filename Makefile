PYTHON ?= python3
export PYTHONPATH := src

DATA    := data
MODELS  := models
BASELINE := $(DATA)/baseline.jsonl
EVENTS   := $(DATA)/events.jsonl
FINDINGS := $(DATA)/findings.jsonl
MODEL    := $(MODELS)/telemetry.json
MINUTES  ?= 1440

.PHONY: help install test lint demo baseline events model detect evaluate asff pipeline clean layer

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

install: ## install the package with dev extras
	$(PYTHON) -m pip install -e ".[dev]"

test: ## run the test suite
	$(PYTHON) -m pytest -q

lint: ## static checks
	$(PYTHON) -m ruff check src tests infra/lambda

demo: ## run the whole pipeline in memory and print the scorecard
	$(PYTHON) -m gsd.cli demo --minutes $(MINUTES)

baseline: ## generate a clean day of operations (training data)
	@mkdir -p $(DATA)
	$(PYTHON) -m gsd.cli simulate --minutes $(MINUTES) --seed 43 --attacks none --out $(BASELINE)

events: ## generate a day of operations with every attack injected
	@mkdir -p $(DATA)
	$(PYTHON) -m gsd.cli simulate --minutes $(MINUTES) --out $(EVENTS)

model: baseline ## fit the telemetry baseline model
	@mkdir -p $(MODELS)
	$(PYTHON) -m gsd.cli train --events $(BASELINE) --out $(MODEL)

detect: events model ## run the detection engine
	$(PYTHON) -m gsd.cli detect --events $(EVENTS) --model $(MODEL) --out $(FINDINGS)

evaluate: detect ## score the detections against the injected ground truth
	$(PYTHON) -m gsd.cli evaluate --events $(EVENTS) --findings $(FINDINGS)

asff: detect ## render the findings as ASFF (Security Hub format)
	$(PYTHON) -m gsd.cli asff --findings $(FINDINGS) --out $(DATA)/asff.json

pipeline: evaluate asff ## full offline pipeline

layer: ## build the Lambda layer for deployment
	./infra/build_layer.sh

clean:
	rm -rf $(DATA)/*.jsonl $(DATA)/asff.json $(MODELS)/*.json build .pytest_cache .ruff_cache

PYTHON ?= python3
IMAGE ?= ghcr.io/rogerbergling/haproxy-analytics:local

.PHONY: help run demo test validate smoke verify docker-build docker-run

help:
	@echo "HAProxy Analytics targets:"
	@echo "  make run           start the server with the configured log source"
	@echo "  make demo          start with the bundled synthetic demo log"
	@echo "  make test          run the Python unit tests"
	@echo "  make smoke         start the real server with demo data and check endpoints"
	@echo "  make verify        check the public repository for missing or unsafe content"
	@echo "  make validate      compile, test, verify and smoke-test"
	@echo "  make docker-build  build the local container image"
	@echo "  make docker-run    run the local image on 127.0.0.1:8080 with demo data"

run:
	$(PYTHON) -m haproxy_analytics

demo:
	$(PYTHON) -m haproxy_analytics --demo --bind 127.0.0.1 --port 8080

test:
	$(PYTHON) -m unittest discover -s tests -t . -v

smoke:
	$(PYTHON) scripts/smoke.py

verify:
	$(PYTHON) scripts/verify.py

validate:
	$(PYTHON) -m compileall -q haproxy_analytics tests scripts
	@if command -v node >/dev/null 2>&1; then node --check public/assets/app.js; else echo "node not installed; skipping JavaScript syntax check"; fi
	$(PYTHON) -m unittest discover -s tests -t . -v
	$(PYTHON) scripts/verify.py
	$(PYTHON) scripts/smoke.py

docker-build:
	docker build -t $(IMAGE) .

docker-run:
	docker run --rm -p 127.0.0.1:8080:8080 \
		-e DEMO_MODE=true \
		-e HAPROXY_LOG_FILE= \
		--read-only --cap-drop=ALL \
		--security-opt=no-new-privileges:true \
		--tmpfs /tmp:rw,noexec,nosuid,size=32m \
		$(IMAGE)

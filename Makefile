# Convenience targets for aws-codegen. The CI gate runs the same checks directly;
# these are for local use. See README.md.

MODELS = \
	models/dynamodb/2012-08-10/service-2.json:generated/dynamodb/dynamodb.zap \
	models/sqs/2012-11-05/service-2.json:generated/sqs/sqs.zap \
	models/kinesis/2013-12-02/service-2.json:generated/kinesis/kinesis.zap

.PHONY: sync sync-check generate test fmt check

## sync: snapshot the manifest's services from the pinned botocore into models/
sync:
	python3 tools/sync-models.py

## sync-check: verify models/ matches the pin without writing (needs network)
sync-check:
	python3 tools/sync-models.py --check

## generate: regenerate every checked-in client from its snapshot model
generate:
	@for pair in $(MODELS); do \
		model=$${pair%%:*}; out=$${pair##*:}; \
		echo "aws-codegen $$model -> $$out"; \
		cargo run --quiet --locked -- "$$model" -o "$$out"; \
	done

## test: the host-only fidelity gate (no Zap toolchain / Docker)
test:
	cargo test --locked
	python3 tools/verify_describe_table.py
	python3 tools/verify_goldens.py

## fmt: format the Rust sources
fmt:
	cargo fmt

## check: the host half of the CI gate
check:
	cargo fmt --check
	cargo clippy --all-targets --locked -- -D warnings
	cargo build --locked
	$(MAKE) test

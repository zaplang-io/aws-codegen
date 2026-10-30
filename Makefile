# Convenience targets for aws-codegen. The CI gate runs the same checks directly;
# these are for local use. See README.md.

# service:api_version pairs — each regenerates the zenv package generated/<svc>/
# (zap.toml + src/<svc>.zap) from models/<svc>/<api_version>/service-2.json.
# Keep in sync with models/manifest.json and the CI "generated output is current"
# step.
SERVICES = \
	dynamodb:2012-08-10 \
	sqs:2012-11-05 \
	kinesis:2013-12-02 \
	lambda:2015-03-31 \
	cloudfront:2015-09-17 \
	sdb:2009-04-15 \
	ec2:2016-11-15 \
	sts:2011-06-15 \
	s3:2006-03-01 \
	sns:2010-03-31 \
	iam:2010-05-08

.PHONY: sync sync-check generate test fmt check

## sync: snapshot the manifest's services from the pinned botocore into models/
sync:
	python3 tools/sync-models.py

## sync-check: verify models/ matches the pin without writing (needs network)
sync-check:
	python3 tools/sync-models.py --check

## generate: regenerate every checked-in client package from its snapshot model
generate:
	@for pair in $(SERVICES); do \
		svc=$${pair%%:*}; ver=$${pair##*:}; \
		model=models/$$svc/$$ver/service-2.json; \
		echo "aws-codegen $$model -> generated/$$svc/ (package)"; \
		cargo run --quiet --locked -- "$$model" --package "generated/$$svc" --name "$$svc"; \
	done

## test: the host-only fidelity gate (no Zap toolchain / Docker)
test:
	cargo test --locked
	python3 tools/verify_describe_table.py
	python3 tools/verify_goldens.py
	python3 tools/verify_lambda_requests.py
	python3 tools/verify_xml_requests.py

## fmt: format the Rust sources
fmt:
	cargo fmt

## check: the host half of the CI gate
check:
	cargo fmt --check
	cargo clippy --all-targets --locked -- -D warnings
	cargo build --locked
	$(MAKE) test

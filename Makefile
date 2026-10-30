# Convenience targets for aws-codegen. The CI gate runs the same checks directly;
# these are for local use. See README.md.

# The set of generated services is driven entirely by models/manifest.json
# (#364 broad rollout): tools/manifest_services.py prints one
# "<service>\t<api_version>\t<package>" line per entry, and the generate target,
# the CI "generated output is current" step and the Rust determinism test all
# consume that same list. Adding/removing a service is a one-line manifest edit.

.PHONY: sync sync-check generate test fmt check

## sync: snapshot the manifest's services from the pinned botocore into models/
sync:
	python3 tools/sync-models.py

## sync-check: verify models/ matches the pin without writing (needs network)
sync-check:
	python3 tools/sync-models.py --check

## generate: regenerate every checked-in client package from its snapshot model
generate:
	@cargo build --quiet --locked
	@python3 tools/manifest_services.py | while IFS="$$(printf '\t')" read -r svc ver pkg; do \
		model=models/$$svc/$$ver/service-2.json; \
		echo "aws-codegen $$model -> generated/$$pkg/ (package)"; \
		./target/debug/aws-codegen "$$model" --package "generated/$$pkg" --name "$$pkg"; \
	done

## test: the host-only fidelity gate (no Zap toolchain / Docker)
test:
	cargo test --locked
	python3 tools/verify_describe_table.py
	python3 tools/verify_goldens.py
	python3 tools/verify_lambda_requests.py
	python3 tools/verify_xml_requests.py
	python3 tools/verify_cbor_requests.py

## fmt: format the Rust sources
fmt:
	cargo fmt

## check: the host half of the CI gate
check:
	cargo fmt --check
	cargo clippy --all-targets --locked -- -D warnings
	cargo build --locked
	$(MAKE) test

# No testdata files to embed for this repository
# Tests use direct filesystem access instead of embedded fixtures

.PHONY: update-bindata
update-bindata:
	@echo "No testdata files to generate (tests use direct filesystem access)"

.PHONY: verify-bindata
verify-bindata:
	@echo "No testdata files to verify"

.PHONY: bindata
bindata: update-bindata

.PHONY: clean-bindata
clean-bindata:
	@echo "No bindata files to clean"

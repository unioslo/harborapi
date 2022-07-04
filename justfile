default_scanner_version := "1.1"

# Fetch newest swagger.yaml from Harbor repo
_fetchswagger:
    mkdir -p codgen && curl https://raw.githubusercontent.com/goharbor/harbor/main/api/v2.0/swagger.yaml --output codegen/swagger.yaml

# Generate models from swagger.yaml
_codegen:
    datamodel-codegen --input codegen/swagger.yaml --output codegen/model.py

# Fetch swagger.yaml and generate models
fetchgen: _fetchswagger _codegen
    # Finished fetching new definitions and generating models

_fetchswagger_scanner_1_0:
    mkdir -p codgen && curl https://raw.githubusercontent.com/goharbor/pluggable-scanner-spec/master/api/spec/scanner-adapter-openapi-v1.0.yaml --output codegen/scanner-adapter-openapi-v1.0.yaml

_fetchswagger_scanner_1_1:
    mkdir -p codgen && curl https://raw.githubusercontent.com/goharbor/pluggable-scanner-spec/master/api/spec/scanner-adapter-openapi-v1.1.yaml --output codegen/scanner-adapter-openapi-v1.1.yaml

_fetchswagger_scanner version:
    @echo "Fetching Pluggable Scanner API Spec version {{ version }}"
    mkdir -p codgen && curl https://raw.githubusercontent.com/goharbor/pluggable-scanner-spec/master/api/spec/scanner-adapter-openapi-v{{version}}.yaml --output codegen/scanner-adapter-openapi-v{{version}}.yaml

_codegen_scanner version:
    @echo "Creating Pluggable Scanner Models"
    datamodel-codegen --input codegen/scanner-adapter-openapi-v{{version}}.yaml --input-file-type openapi --output codegen/model_scanner.{{version}}.py

fetchgenscanner version=default_scanner_version: (_fetchswagger_scanner version) (_codegen_scanner version)
    # Finished fetching new definitions and generating models


# Test
test:
    pytest -vv

# Coverage in terminal
_cov:
    coverage run --source=. -m pytest

testcov: _cov
    coverage report -m

testhtml: _cov
    coverage html && google-chrome htmlcov/index.html

# Run pre-commit hooks on all files
pcrun:
    pre-commit run --all-files

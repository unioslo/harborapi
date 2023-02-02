# Coverage in terminal
_cov:
    -coverage run --source=. -m pytest

# Test
test:
    pytest -vv

# Test and display coverage in terminal
testcov: _cov
    coverage report -m

# Test and display coverage in browser
testhtml: _cov
    coverage html && google-chrome htmlcov/index.html

# Run pre-commit hooks on all files
pcrun:
    -pre-commit run --all-files


# Recipes for generating Pydantic models from Swagger API schemas
codegendir := "codegen"
default_scanner_version := "1.1"

# Make codegen directory
mkcodegendir:
    mkdir -p {{codegendir}}

# Generate new Harbor API models
genapi: mkcodegendir
    curl \
        https://raw.githubusercontent.com/goharbor/harbor/main/api/v2.0/swagger.yaml \
        --output codegen/swagger.yaml
    datamodel-codegen \
        --input codegen/swagger.yaml  \
        --output codegen/_models.py \
        --base-class .base.BaseModel
    # Finished fetching new definitions and generating models for the Harbor API

# Generate new Scanner API models
genscanner version=default_scanner_version: mkcodegendir
    curl \
        https://raw.githubusercontent.com/goharbor/pluggable-scanner-spec/master/api/spec/scanner-adapter-openapi-v1.1.yaml \
        --output {{codegendir}}/scanner-adapter-openapi-v1.1.yaml
    datamodel-codegen \
        --input codegen/scanner-adapter-openapi-v{{version}}.yaml \
        --input-file-type openapi --output codegen/_scanner.py \
        --base-class .base.BaseModel
    # Finished fetching new definitions and generating models for the Harbor Pluggable Scanner API

docs_addr := "localhost:8000"
# Serve docs locally
serve addr=docs_addr:
    mkdocs serve -a {{addr}}

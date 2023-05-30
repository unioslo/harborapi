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
    coverage html && open htmlcov/index.html

# Run pre-commit hooks on all files
pcrun:
    -pre-commit run --all-files


# Recipes for generating Pydantic models from Swagger API schemas
codegendir := "codegen"
default_scanner_version := "1.1"

datamodel_codegen_opts := (
    "--base-class .base.BaseModel \
    --field-constraints \
    --target-python-version 3.8 \
    "
)

# Make codegen directory
mkcodegendir:
    mkdir -p {{codegendir}}


# Generate new Harbor API models
genapi: mkcodegendir
    datamodel-codegen \
        --url https://raw.githubusercontent.com/goharbor/harbor/main/api/v2.0/swagger.yaml  \
        --output ./harborapi/models/_models.py \
        {{datamodel_codegen_opts}}
    black ./harborapi/models/_models.py
    # Finished fetching new definitions and generating models for the Harbor API

# Generate new Scanner API models
genscanner: mkcodegendir
    datamodel-codegen \
        --url https://raw.githubusercontent.com/goharbor/pluggable-scanner-spec/master/api/spec/scanner-adapter-openapi-v1.1.yaml \
        --output ./harborapi/models/_scanner.py \
        --input-file-type openapi \
        {{datamodel_codegen_opts}}
    black ./harborapi/models/_scanner.py
    # Finished fetching new definitions and generating models for the Harbor Pluggable Scanner API

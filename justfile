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


# Generate new Harbor API models
genapi:
    datamodel-codegen \
        --url https://raw.githubusercontent.com/goharbor/harbor/main/api/v2.0/swagger.yaml  \
        --output ./harborapi/models/_models.py
    black ./harborapi/models/_models.py
    # Finished fetching new definitions and generating models for the Harbor API

# Generate new Scanner API models
genscanner:
    datamodel-codegen \
        --url https://raw.githubusercontent.com/goharbor/pluggable-scanner-spec/master/api/spec/scanner-adapter-openapi-v1.1.yaml \
        --output ./harborapi/models/_scanner.py \
        --input-file-type openapi
    black ./harborapi/models/_scanner.py
    # Finished fetching new definitions and generating models for the Harbor Pluggable Scanner API

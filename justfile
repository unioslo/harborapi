# Fetch newest swagger.yaml from Harbor repo
_fetchswagger:
    mkdir -p codgen && curl https://raw.githubusercontent.com/goharbor/harbor/main/api/v2.0/swagger.yaml --output codegen/swagger.yaml

# Generate models from swagger.yaml
_codegen:
    datamodel-codegen --input codegen/swagger.yaml --output codegen/model.py

# Fetch swagger.yaml and generate models
fetchgen: _fetchswagger _codegen
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

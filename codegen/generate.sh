#!/bin/bash

mkdir -p ./codegen/temp

datamodel-codegen \
  --url https://converter.swagger.io/api/convert?url=https://raw.githubusercontent.com/goharbor/harbor/main/api/v2.0/swagger.yaml  \
  --output ./codegen/temp/_models.py

python codegen/ast/parser.py ./codegen/temp/_models.py ./codegen/temp/models.py
isort ./codegen/temp/models.py
black ./codegen/temp/models.py

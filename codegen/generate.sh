#!/bin/bash

# Display help message
if [[ "$1" == "--help" ]]; then
  echo "USAGE: generate.sh [main|scanner] [--no-fetch]"
  exit 0
fi

# TODO: use https://github.com/RonnyPfannschmidt/prance
#       instead of relying on swagger converter API

# Initialize variable to determine whether codegen should run
fetch_spec=true

# Default values for source_url, output_file, final_file, and source_type
source_url="https://raw.githubusercontent.com/goharbor/harbor/main/api/v2.0/swagger.yaml"
output_file="./codegen/temp/_models.py"
final_file="./codegen/temp/models.py"
source_type="main"  # default source type

# Check for optional positional argument for source ('main' or 'scanner')
if [[ "$1" == "scanner" ]]; then
  source_url="https://raw.githubusercontent.com/goharbor/pluggable-scanner-spec/master/api/spec/scanner-adapter-openapi-v1.1.yaml"
  output_file="./codegen/temp/_scanner.py"
  final_file="./codegen/temp/scanner.py"
  source_type="scanner"
elif [[ "$1" != "" && "$1" != "main" ]]; then
  echo "Invalid argument: $1. Please use 'main' or 'scanner'. Defaulting to 'main'."
fi

# Loop through command line arguments for flags
for arg in "$@"; do
  case $arg in
    --no-fetch)
      fetch_spec=false
      shift # Remove --no-fetch from processing
      ;;
    *)
      shift # Remove generic argument from processing
      ;;
  esac
done

mkdir -p ./codegen/temp

# Run datamodel-codegen only if fetch_spec is true
if [ "$fetch_spec" = true ]; then
  datamodel-codegen \
    --url "https://converter.swagger.io/api/convert?url=$source_url" \
    --output "$output_file"
fi

python codegen/ast/parser.py "$output_file" "$final_file" "$source_type"
ruff check --fix "$final_file"
ruff format "$final_file"
cp "$final_file" "./harborapi/models/$(basename "$final_file")"

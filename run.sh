#!/bin/bash
# Helper script to run with .env loaded

# Load environment variables
set -a
source .env
set +a

# Run the script with all arguments passed through
python3 script.py "$@"

#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
if [ ! -f "$DIR/venv/bin/python" ]; then
    echo "Virtual environment not found. Run ./setup.sh first."
    exit 1
fi
"$DIR/venv/bin/python" -m cloudsec_scanner.cli "$@"

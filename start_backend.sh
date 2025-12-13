#!/bin/bash
echo "Starting CyberNews Backend..."
cd "$(dirname "$0")/backend"
python app.py

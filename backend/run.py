#!/usr/bin/env python3
"""Start backend in simple mode"""
import os
import sys

# Change to backend directory
os.chdir(os.path.dirname(__file__))

# Set environment
os.environ['PYTHONIOENCODING'] = 'utf-8'
os.environ['FLASK_ENV'] = 'production'

# Import and run Flask app
from app import app, socketio

if __name__ == "__main__":
    try:
        print("🚀 Starting Cyber-Guard Backend Server...")
        print("📡 Server: http://localhost:5000")
        socketio.run(app, host='0.0.0.0', port=5000, debug=False)
    except KeyboardInterrupt:
        print("\n⏹️ Server stopped")
        sys.exit(0)
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)

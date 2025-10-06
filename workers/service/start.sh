#!/bin/bash
# Start the Shells Worker Service

cd "$(dirname "$0")"

# Activate virtual environment
source ../venv/bin/activate

# Start FastAPI service
echo "🚀 Starting Shells Worker Service on http://localhost:8000"
echo "📚 API docs available at http://localhost:8000/docs"
echo ""

uvicorn main:app --host 0.0.0.0 --port 8000 --reload

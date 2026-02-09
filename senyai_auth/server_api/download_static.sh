#!/usr/bin/env bash

mkdir -p "static"

echo "Starting download of dependencies..."

if [ ! -f "static/swagger-ui-bundle.js" ]; then
  curl -L https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js -o "static/swagger-ui-bundle.js"
else
  echo "swagger-ui-bundle.js already exists."
fi

if [ ! -f "static/swagger-ui.css" ]; then
  curl -L https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css -o "static/swagger-ui.css"
else
  echo "swagger-ui.css already exists."
fi

if [ ! -f "static/favicon.png" ]; then
  curl -L https://fastapi.tiangolo.com/img/favicon.png -o "static/favicon.png"
else
  echo "favicon.png already exists."
fi

echo "----------------------------------------"
echo "Installation complete."
echo "----------------------------------------"
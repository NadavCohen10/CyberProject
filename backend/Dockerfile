# Use a Python base image
FROM python:3.11-slim

# Install system dependencies needed for LIEF and general tools
RUN apt-get update && apt-get install -y \
    libxml2 \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the backend code and the model
COPY . .

# The actual command will be handled by docker-compose
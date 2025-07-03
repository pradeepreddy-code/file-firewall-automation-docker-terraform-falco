# Use a lightweight base image
FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Copy only requirements.txt first (leverages Docker layer caching)
COPY requirements.txt .

# Upgrade OS packages to reduce CVEs & clean up
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of your application code
COPY . .

# Expose port Flask listens on inside the container
EXPOSE 5000

# Run the Flask app (make sure app.py uses host="0.0.0.0")
CMD ["python", "app.py"]


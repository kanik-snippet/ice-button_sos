# Use the official Python base image with Python 3.10
FROM python:3.10-slim

# Install system dependencies, including gettext
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    libffi-dev \
    pkg-config \
    default-libmysqlclient-dev \
    gettext \
    redis-server \
    && rm -rf /var/lib/apt/lists/*


# Set the working directory in the container
WORKDIR /app

# Copy the requirements.txt file to the Docker image
COPY requirements.txt .

# Install the Python dependencies
RUN pip install --no-cache-dir --disable-pip-version-check -r requirements.txt


# Copy the entire project to the Docker image
COPY . .

# Expose the port Django will run on (default 8000)
EXPOSE 8058

# Run migrations and create a superuser, then start the Django application
CMD ["sh", "/app/entrypoint.sh"]

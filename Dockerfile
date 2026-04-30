# Use a stable Python 3.10 image
FROM python:3.10-slim

# Install system dependencies for OpenCV, Tesseract, and PDF processing
RUN apt-get update && apt-get install -y \
    libgl1 \
    libglib2.0-0 \
    tesseract-ocr \
    libtesseract-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Set environment variables
ENV PYTHONPATH=/app
ENV PORT=7860
ENV PYTHONUNBUFFERED=1

# Expose the Hugging Face default port
EXPOSE 7860

# Ensure start.sh is executable and start the system
RUN chmod +x start.sh
CMD ["/bin/sh", "start.sh"]

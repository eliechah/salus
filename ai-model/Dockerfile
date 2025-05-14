# ai-model/Dockerfile

FROM python:3.10-slim

# Install dependencies
RUN pip install tensorflow scikit-learn

# Create app directory
WORKDIR /app

# Copy your model files
COPY ai_filter.py kdnn_model.keras tokenizer.pkl /app/

# Optional: set a test command for now
CMD ["python3", "ai_filter.py"]
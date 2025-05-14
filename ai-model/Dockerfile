FROM python:3.10-slim

WORKDIR /app

# Install dependencies
RUN pip install tensorflow scikit-learn

# Copy code
COPY ai_filter.py kdnn_model.keras tokenizer.pkl github_scan_handler.py /app/

CMD ["python3", "github_scan_handler.py"]

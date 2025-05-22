FROM python:3.10-slim

WORKDIR /app

# Install system-level dependencies
RUN apt-get update && apt-get install -y yara git curl && apt-get clean

# Install Semgrep and Gitleaks
RUN pip install semgrep

# Install Gitleaks from source using Go
RUN apt-get update && apt-get install -y curl jq && \
    export VERSION=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest | jq -r .tag_name) && \
    curl -L -o gitleaks.tar.gz https://github.com/gitleaks/gitleaks/releases/download/${VERSION}/gitleaks_${VERSION#v}_linux_x64.tar.gz && \
    tar -xzf gitleaks.tar.gz && mv gitleaks /usr/local/bin/ && rm gitleaks.tar.gz


# Install Python dependencies
RUN pip install tensorflow scikit-learn

# Copy only the required files
COPY ai_filter.py kdnn_model.keras tokenizer.pkl output_handler.py /app/

ENV TF_CPP_MIN_LOG_LEVEL=3
ENV CUDA_VISIBLE_DEVICES=-1

# Set the default command to run your unified AI scanner
CMD ["python3", "output_handler.py"]

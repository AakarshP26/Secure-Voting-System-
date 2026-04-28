FROM python:3.12-slim

# Set environment variables to prevent Python from buffering stdout/stderr
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install system dependencies (required for some crypto/compile steps if needed, though pure python works here)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire project
COPY . .

# Expose ports for FastAPI (65432) and Streamlit (8501)
EXPOSE 65432
EXPOSE 8501

# Create a robust startup script
RUN echo '#!/bin/bash\n\
echo "Starting Quantum-Secure Messaging Platform..."\n\
# Seed the database with two demo users\n\
python backend/register.py --user alice --password secret\n\
python backend/register.py --user bob --password secret\n\
echo "[OK] Demo users alice and bob registered (password: secret)"\n\
\n\
# Start FastAPI backend in the background\n\
uvicorn backend.server_async:app --host 0.0.0.0 --port 65432 &\n\
\n\
# Give backend a moment to initialize\n\
sleep 3\n\
\n\
# Start Streamlit in the foreground\n\
streamlit run frontend/app.py --server.port 8501 --server.address 0.0.0.0\n\
' > start.sh

RUN chmod +x start.sh

# Run the startup script
CMD ["./start.sh"]

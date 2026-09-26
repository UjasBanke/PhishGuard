FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# Re-train inside the image so the pickle matches the installed scikit-learn
RUN python train.py
EXPOSE 8000 8501
# Default: API. docker-compose overrides the command for the dashboard.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

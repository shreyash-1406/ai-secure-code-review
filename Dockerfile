FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd -m reviewer && chown -R reviewer /app
USER reviewer
ENV REVIEW_DB=/app/data/reviews.db
RUN mkdir -p /app/data
EXPOSE 5000
CMD ["gunicorn", "-b", "0.0.0.0:5000", "--timeout", "300", "run:app"]

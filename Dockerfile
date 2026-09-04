FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Train machine learning models
RUN python "Final Year project/phishing_detection_framework/model/train_model.py"

EXPOSE 5000

ENV PORT=5000

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "wsgi:app"]

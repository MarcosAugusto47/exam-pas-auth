FROM python:3.11

COPY app /app/
#COPY app/encodings/encoding_category.pickle .
COPY pipelines/features /pipelines/features/
#COPY ../pipelines/models/config.py .

RUN pip install -r app/requirements.txt

COPY . .

CMD ["python", "app/app.py"]

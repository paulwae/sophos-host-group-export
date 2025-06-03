FROM python:3.12-slim

WORKDIR /app
COPY sophos-host-group-export.py /app/

RUN pip install --no-cache-dir lxml

ENTRYPOINT ["python", "/app/sophos-host-group-export.py"]
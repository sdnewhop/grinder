# Build Grinder Map
FROM python:3.7-alpine AS grinder-map-build

LABEL org.label-schema.name="Grinder Framework" \
      org.label-schema.description="Python framework to automatically discover and enumerate hosts" \
      org.label-schema.license="GPL-2.0"

COPY ./map /app/
RUN pip install --no-cache-dir flask

WORKDIR /app
ENV PYTHONPATH="/app"
EXPOSE 5000
ENTRYPOINT ["python3", "app.py"]

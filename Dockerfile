FROM python:3.12-slim

# iproute2 provides `tc`, which we use to add artificial network delay.
RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

ENTRYPOINT ["python", "-m", "twoparty"]

# build stage
FROM python:3.11-alpine as builder
WORKDIR /usr/src/mreg
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

RUN apk update
RUN apk add --virtual build-deps gcc python3-dev openldap-dev musl-dev git
COPY . .
COPY --from=ghcr.io/astral-sh/uv:0.4.30 /uv /uvx /bin/
RUN  uv venv \
    && uv sync --frozen --no-dev  \
    && uv pip compile pyproject.toml -o requirements.txt \
    && uv run python -m ensurepip --upgrade \
    && uv run python -m pip wheel --no-cache-dir --wheel-dir /usr/src/mreg/wheels -r requirements.txt \
    && uv build --wheel --out-dir /usr/src/mreg/wheels

ENTRYPOINT [ "/bin/sh" ]

# final stage
FROM python:3.11-alpine
EXPOSE 8000

COPY entrypoint* manage.py /app/
COPY mreg /app/mreg/
COPY mregsite /app/mregsite/
RUN  mkdir /app/logs
COPY hostpolicy /app/hostpolicy/
COPY --from=builder /usr/src/mreg/wheels /wheels
COPY --from=ghcr.io/astral-sh/uv:0.4.30 /uv /uvx /bin/
RUN apk update && apk upgrade \
    && apk add libldap vim findutils \
    && uv venv \
    && uv pip install --no-cache /wheels/*
RUN chmod a+x /app/entrypoint*

CMD /app/entrypoint.sh

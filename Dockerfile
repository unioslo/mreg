# build stage
FROM python:3.11-alpine AS builder
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apk update
RUN apk add --virtual build-deps gcc python3-dev openldap-dev musl-dev git
# Copy entire build context to the image.
# In order to build the project, we need both the .git directory and project files.
# However, we cannot mix files and directories in the COPY command, because
# COPY will unpack the contents of source directories into the target directory,
# and we need to keep the .git directory intact.
# The workaround is to copy everything, but limit it with .dockerignore.
COPY --from=ghcr.io/astral-sh/uv:0.6.16 /uv /uvx /bin/
COPY . .
# Build and install dependencies
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-editable --no-dev

ENTRYPOINT [ "/bin/sh" ]

# final stage
FROM python:3.11-alpine
EXPOSE 8000

# Don't allow uv to download anything
ENV UV_OFFLINE=1

# Copy over venv with all installed dependencies
COPY --from=builder --chown=app:app /app/.venv /app/.venv

# Copy over application files
COPY entrypoint* manage.py /app/
COPY mreg /app/mreg/
COPY mregsite /app/mregsite/
COPY hostpolicy /app/hostpolicy/
COPY --from=ghcr.io/astral-sh/uv:0.6.16 /uv /uvx /bin/
WORKDIR /app
RUN apk update && apk upgrade \
    && apk add libldap vim findutils \
    && rm -rf /var/cache/apk/* \
    && mkdir -p /app/logs \
    && chmod a+x /app/entrypoint*

CMD /app/entrypoint.sh

# build stage
FROM python:3.10-alpine as builder
WORKDIR /usr/src/mreg
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

RUN apk update
RUN apk add --virtual build-deps gcc python3-dev openldap-dev musl-dev
RUN pip install --upgrade pip
COPY requirements*.txt ./
RUN pip wheel --no-cache-dir --wheel-dir /usr/src/mreg/wheels -r requirements.txt

# final stage
FROM alpine:3.17
EXPOSE 8000

COPY requirements*.txt entrypoint* manage.py /app/
COPY mreg /app/mreg/
COPY hostpolicy /app/hostpolicy/
COPY --from=builder /usr/src/mreg/wheels /wheels
RUN apk update && apk upgrade \
    && apk add python3 py3-pip libldap vim findutils \
    && pip install --upgrade pip \
    && pip install --no-cache /wheels/*
RUN chmod a+x /app/entrypoint*

CMD /app/entrypoint.sh

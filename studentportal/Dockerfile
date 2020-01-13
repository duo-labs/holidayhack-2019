FROM python:3-alpine

RUN apk add --no-cache git bash
RUN pip install requests

WORKDIR /opt
RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev

WORKDIR /opt/sqlmap-dev
CMD ["python", "sqlmap.py"]

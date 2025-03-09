FROM python:3.12 AS ca

WORKDIR /usr/src/app
COPY app/ .
COPY requirements.txt .
RUN rm -rf ocsp_server

RUN pip install --no-cache-dir -r requirements.txt
ENV PYTHONPATH="${PYTHONPATH}:/usr/src/"

CMD ["python", "ca_server/run.py"]

FROM python:3.12 AS ocsp

WORKDIR /usr/src/app
COPY app/ .
COPY requirements.txt .
RUN rm -rf ca_server

RUN pip install --no-cache-dir -r requirements.txt
ENV PYTHONPATH="${PYTHONPATH}:/usr/src/"

CMD ["python", "ocsp_server/run.py"]
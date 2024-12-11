FROM python:3.12 AS ca

WORKDIR /usr/src/app
COPY . .

RUN pip install --no-cache-dir -r requirements.txt

WORKDIR /usr/src/app/ca

CMD ["uvicorn", "main:app", "--host=0.0.0.0", "--port=8000"]

FROM python:3.12 AS ocsp

WORKDIR /usr/src/app
COPY . .

RUN pip install --no-cache-dir -r requirements.txt

WORKDIR /usr/src/app/ocsp_responder

CMD ["uvicorn", "main:app", "--host=0.0.0.0", "--port=8001"]
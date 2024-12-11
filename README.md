# SandiaCA
Sandia National Labs' PKI management tool for the EVs@Scale project

## Services
- ca: Digital certificate management
- ocsp_server: OCSP server for the certificates issued by the CAs

## Prerequisite

Have `docker` and `python >= 3.12` installed.

## Guide

1. Clone this repository and go to the root directory.
2. Start the docker containers with `docker compose up -d`.
3. To generate new certificate bundle, run the `generate_bundle.py` script inside the `examples` directory.
4. (Optional) To test the OCSP server, run the `test_ocsp.py` script inside the `ocsp_responder` directory with `pytest`.

### Notes
1. Modify the `generate_bundle.py` and the `generate_profiles.py` if needed, before generating the certs.
2. The generated certs and relevant keys will be inside the `vault` directory, organized according to the EVerest and MaEVe file structure.
3. Currently, the data in the container do not persist.

## Author

* **Md Sahabul Hossain** - [sahabulh](https://github.com/sahabulh) - msahabulhossain@gmail.com
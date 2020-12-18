FROM python:3-alpine
MAINTAINER guanana2
RUN apk add --no-cache nmap
WORKDIR /usr/src/netbox-scanner
COPY . .
RUN pip3 --disable-pip-version-check --no-cache-dir install -r requirements.txt && rm requirements.txt
ENTRYPOINT ["python3", "netbox-scanner.py"]

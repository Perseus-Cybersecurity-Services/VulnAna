# VulnAna
VulnAna (Vulnerability Analyzer) is a tool to extract information on reports, assets and vulnerabilities of Greenbone Vulnerability Maganement (GVM) automatically, procces and send it to ElasticSearch, Opendistro or OpenSearch.

![Version](https://img.shields.io/badge/version-1.0.0-blue)

![PErseus](./resources/Perseus-Logo-Htal.png)

![VulnAna dashboards](./resources/VulnAna-dashboards.png)

## Table of Contents
 - [Features](#features)
 - [Prerequisites](#prerequisites)
 - [Installation/Deployment](#installationdeployment)
 - [Important notes](#important-notes)
 - [Support](#support)
 - [Maintainer](#maintainer)

## Features
- VulnAna is intended to work with multiple independent users (More on how to create a new one is explained later)
- VulnAna is prepared to collect information from two GVM instances per user. One for external and other for internal scans, but having both is optional.
- The information from GVM is processed:
    - Interesting fields are **parsed**.
    - The information from different GVM reports is **unified**.
    - The information is **enriched** by adding labels and categories to assets.
    - **Scores** are calculated to define the "health" of users in the cybersecurity area.

## Prerequisites
In the installation machine:
- Docker (and docker compose submodule) [[Docker installation Guide]](https://docs.docker.com/engine/install/)

In the same or remote machine:
- Vulnerability Scanner:
    - Greenbone Vulnerability Magamement (+20.08) [[Docker installation Guide by Secure Compliance]](https://securecompliance.gitbook.io/projects/)

- Storage and Visualization:
    - ElasticSearch and Kibana (From Elastic stack or Opendistro) [[Official installation Guide]](https://opendistro.github.io/for-elasticsearch-docs/docs/install/)
    - OpenSearch and OpenSearch Dashboards [[Official installation Guide]](https://opensearch.org/docs/latest/install-and-configure/install-opensearch/index/)

## Installation/Deployment

### Download and build VulnAna

```bash
$ git clone https://github.com/Perseus-Cybersecurity-Services/vulnana
$ cd vulnana/
$ docker build -t vulnana:latest -f app/Dockerfile .
```

### Import dashboards to Kibana
- Enter kibana -> Stack Management -> Saved Objects -> "Import" and select VulnAna/recourses/VulnAna-kibana-objects.ndjson

### Add a new user
1. Add a line with the format \<username\>:\<salted_MD5_password\> in nginx/.htpasswd
2. Add a section in app/config/user_config.ini with the **SAME** username created for that company with following fields:

> NOTE: In this version, authentication takes place on the Nginx reverse proxy. This means that if you don't follow the steps in this guide and build the API without using Nginx, the API will not check if the passwords are correct when accessing the "auth/login" endpoint. If you use the docker-compose.yml file of this repository and you configure the user and certificates correctly, Nginx will manage the authentication.

- **external_scans** (*Boolean*): True if there is an instance to perform external scans
- **gvm_external_host** (*str*): Optional, hostname or IP of the external instance of GVM 
- **gvm_external_port** (*int*): Optional, TLS port of the external instance of GVM
- **gvm_external_username** (*str*): Optional, username of the external instance of GVM. It is highly recommended to create a user with role "user" in GVM
- **gvm_external_password** (*str*): Optional, password of the external instance of GVM

- **internal_scans** (*Boolean*): True if there is an instance to perform internal scans
- **gvm_internal_host** (*str*): Optional, hostname or IP of the internal instance of GVM
- **gvm_internal_port** (*int*): Optional, TLS port of the internal instance of GVM
- **gvm_internal_username** (*str*): Optional, username of the internal instance of GVM. It is highly recommended to create a user with role "user" in GVM
- **gvm_internal_password** (*str*): Optional, password of the external instance of GVM

- **elasticsearch_host** (*str*): hostname or IP of ElasticSearch instance
- **elasticsearch_port** (*int*): port of ElasticSearch instance
- **elasticsearch_username** (*str*): ElasticSearch user's username. It is highly recommended to create a specific user for this connector that has only the essential permissions to read and write to the VulnAna indices.
- **elasticsearch_password** (*str*): ElasticSearch user's password.
- **elastic_use_certs** (*Boolean*): True if you want to force the use of client certificates for connections to elasticsearch
- **elastic_ca_cert** (*str*): Optional, path to root CA 
- **elastic_client_cert** (*str*): Optional, path to client certificate
- **elastic_client_key** (*str*): Optional, path to client certificate key

### Generate keys
VulnAna needs two keys to be generated:
- CONFIG_DECRYPT_KEY: Used for encrypting sensitive fields in the configuration.
- APP_SECRET_KEY: Used for generating json web tokens.

> NOTE: This is just an example, there are multiple valid ways of generating keys


```python
$ python3
> from cryptography.fernet import Fernet
> print(Fernet.generate_key())
> exit()
```
- Copy generated values to .env-example file
- `mv .env-example .env`

### Encrypt sensitive fields

- First time: create python virtual environment and download dependencies
```bash
$ python -m venv venv
$ source venv/bin/activate
$ pip install -r requirements  
> exit()
```
- Always: Encrypt fields. Make sure you are in the python virtual environment
```python
$ python3
> from app.main.config.user_config import p3_encrypt
> p3_encrypt(b'your string', b'your config key')
```

### Create new self-signed certificates (using OpenSSL)
```bash
$ cd nginx/certs
$ sudo openssl genrsa -des3 -out server.key 4096
$ sudo openssl req -new -key server.key -out server.csr
$ sudo openssl rsa -in server.key.org -out server.key
$ sudo openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt
```

### Start containers
- `docker compose up -d`

### Automation
If you wish, you can set up an "HTTP GET" alert in GVM on tasks so that they notify VulnAna when they are done. VulnAna will then check if all the tasks of that user have finished, and if so, it will collect, process and send the information to ElasticSearch. In GVM, create new Alert and assing it to desired tasks: 
- Name: Alert-VulnAna
- Event: Task run status changed to Done
- Method: HTTP Get
- HTTP Get URL: http://<vulnana_hostname_or_IP+port>/api/v1/vulnana/finished/$n

### Allow a new source IP address in /scan/finished/\<task_name\> endpoint
Add a line with the format: `allow <new IP Address>` in nginx/default.conf inside server/location /api/v1/scan/finished/

## Important notes
- At the moment only the GVM scanner is supported. In addition, the information can only be extracted through TLS method.
- Tasks in GVM must follow \<username\>\_\<internal/external\>\_\<descriptor\> structure. Examples:
    - user1_internal_DMZ
    - user1_internal_datacenter
    - user1_external_web
- Already proccesed reports' ids will be saved into /app/main/files/\<username\>/report_ids.txt. This will avoid from sending duplicated information to ElasticSearch.
- At the moment, kibana visualizations are only available in Spanish. We will translate them to English as soon as possible.

## Support
If you found a problem with the software, please [create an issue](https://github.com/Perseus-Cybersecurity-Services/vulnana/issues) on GitHub.

## Maintainer
This project is maintained by [Perseus Cybersecurity Services](https://github.com/Perseus-Cybersecurity-Services).

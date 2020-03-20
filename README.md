## Cloud-PCAP

A charmingly pathetic knock-off of cloudshark.org that I use for simple cloud pcap storage and very lightweight packet analysis.

## Features

* Easy PCAP uploads
	* Drag & drop on home page
	* Via API (curl, ajax, Wireshark plugins)
* User management
    * PCAPs stored/accessed per user (no sharing yet)
    * Temp password upon account creation
* Packet Overview
    * Capture summary stats
    * [Display Filters](http://wiki.wireshark.org/DisplayFilters)
    * Packet header list
    * Click a packet to see more details 

## Installation/Running

### Pre-requisites
- Docker/Docker-compose

### Config File
Create a `app/config.py` file, E.g.:
```python
#!/usr/bin/env python3

class Config:
    SQLALCHEMY_COMMIT_ON_TEARDOWN = True
    SECRET_KEY = "REPLACE_ME"

```

### Installation Steps

* `$ git clone https://github.com/thepacketgeek/cloud-pcap.git`
* `$ cd cloud_pcap`
* `$ docker-compose up --build`
* `$ docker-compose run app flask shell`
    ```
    >>> init_db()
    >>> quit()
    ```
   	* Default user admin/cloudpcap is now setup

## Screenshots

![screenshot1](docs/cloud-pcap1.png "Screenshot #1")

![screenshot2](docs/cloud-pcap2.png "Screenshot #2")

![screenshot3](docs/cloud-pcap3.png "Screenshot #3")

## Coming Soon

* Group permissions?
* Heroku-Deployment ready
* Display Filtering Auto-complete
* Vagrantfile for quick development environment setup


## Built With...

* [Docker](http://docker.com)
* [Flask](http://flask.pocoo.org)
* [Flask-Bootstrap](http://pythonhosted.org/Flask-Bootstrap/)
* [PyShark](http://kiminewt.github.io/pyshark/)
* [Chartkick](https://github.com/mher/chartkick.py)
* [Highcharts](http://api.highcharts.com/highcharts)
* [Bootstrap-Taginput](http://timschlechter.github.io/bootstrap-tagsinput/examples/)
* [Bootstrap3-Typeahead](https://github.com/bassjobsen/Bootstrap-3-Typeahead)


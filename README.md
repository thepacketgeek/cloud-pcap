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

* `$ git clone https://github.com/thepacketgeek/cloud-pcap.git`
* Install PostgreSQL and create an empty database
	* Put psql path in config.py DevelopmentConfig() class
	* `$ export APP_SETTINGS="config.DevelopmentConfig"`
* `$ cd cloud-pcap`
* `$ pip install -r requirements.txt`
* `$ cd app`
* `$ mkdir static/tracefiles`
* `$ python app.py shell`
    * `>>> init_db`
    * `>>> db.session.commit()`
   	* Default user admin/cloudpcap is now setup
* `$ python app.py runserver`

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

* [Flask](http://flask.pocoo.org)
* [Flask-Bootstrap](http://pythonhosted.org/Flask-Bootstrap/)
* [PyShark](http://kiminewt.github.io/pyshark/)
* [Chartkick](https://github.com/mher/chartkick.py)
* [Highcharts](http://api.highcharts.com/highcharts)
* [Bootstrap-Taginput](http://timschlechter.github.io/bootstrap-tagsinput/examples/)
* [Bootstrap3-Typeahead](https://github.com/bassjobsen/Bootstrap-3-Typeahead)


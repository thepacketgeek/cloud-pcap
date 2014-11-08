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
    * Packet header list
    * Click a packet to see more details 

## Screenshots

![screenshot1](docs/cloud-pcap1.png "Screenshot #1")

![screenshot2](docs/cloud-pcap2.png "Screenshot #2")

## Built With...

* python
* Flask
* Flask-Bootstrap
* Chartkick
* HighCharts
* PyShark
* pcap

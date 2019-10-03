#!/usr/bin/env python3

import os
import datetime
import sys
from io import StringIO

import pyshark

basedir = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(basedir, "static/tracefiles/")


def get_capture_count(filename: str) -> int:
    p = pyshark.FileCapture(
        os.path.join(UPLOAD_FOLDER, filename),
        only_summaries=True,
        keep_packets=False,
        eventloop=loop,
    )
    p.load_packets()
    return len(p)


def decode_capture_file_summary(traceFile, display_filter=None):
    if display_filter:
        cap = pyshark.FileCapture(
            os.path.join(UPLOAD_FOLDER, traceFile.filename),
            keep_packets=False,
            only_summaries=True,
            display_filter=display_filter,
        )
    else:
        cap = pyshark.FileCapture(
            os.path.join(UPLOAD_FOLDER, traceFile.filename),
            keep_packets=False,
            only_summaries=True,
        )

    cap.load_packets(timeout=5)

    if len(cap) == 0:
        return 0, "No packets found or the display filter is invalid."

    details = {
        "stats": {
            "breakdown": {},
            "length_buckets": {
                "0-200": 0,
                "201-450": 0,
                "451-800": 0,
                "801-1200": 0,
                "1201-1500": 0,
            },
        },
        "packets": [],
        # 'linechart': []
    }

    avg_length = []

    def decode_packet(packet):

        pkt_details = {
            "number": packet.no,
            "length": packet.length,
            "time": packet.time,
        }
        pkt_details["src_ip"] = packet.source
        pkt_details["dst_ip"] = packet.destination
        pkt_details["protocol"] = packet.protocol
        pkt_details["desc"] = packet.info

        # delta and stream aren't supported by earlier versions (1.99.1) of tshark
        try:
            pkt_details["delta"] = packet.delta
            pkt_details["stream"] = packet.stream
        except AttributeError:
            pass

        details["packets"].append(pkt_details)
        avg_length.append(int(packet.length))

        if 0 <= int(packet.length) <= 200:
            details["stats"]["length_buckets"]["0-200"] += 1
        elif 201 <= int(packet.length) <= 450:
            details["stats"]["length_buckets"]["201-450"] += 1
        elif 451 <= int(packet.length) <= 800:
            details["stats"]["length_buckets"]["451-800"] += 1
        elif 801 <= int(packet.length) <= 1200:
            details["stats"]["length_buckets"]["801-1200"] += 1
        elif 1201 <= int(packet.length):
            details["stats"]["length_buckets"]["1201-1500"] += 1

        try:
            details["stats"]["breakdown"][packet.protocol] += 1
        except KeyError:
            details["stats"]["breakdown"][packet.protocol] = 1

    try:
        cap.apply_on_packets(decode_packet, timeout=10)
    except:
        return (
            0,
            "Capture File is too large, please try downloading and analyzing locally.",
        )

    details["stats"]["avg_length"] = sum(avg_length) / len(avg_length)

    return len(cap), details


def get_packet_detail(traceFile, number):
    cap = pyshark.FileCapture(os.path.join(UPLOAD_FOLDER, traceFile.filename))

    old_stdout = sys.stdout
    sys.stdout = mystdout = StringIO()

    cap[number - 1].pretty_print()

    sys.stdout = old_stdout

    detail = ""

    for line in mystdout.getvalue().split("\n"):
        if line == "self._packet_string":
            continue
        elif "Layer ETH" in line:
            detail += """<div class="panel panel-default">
                          <div class="panel-heading" role="tab">
                            <h4 class="panel-title">
                              <a class="packetHeader" data-target="#%(link)s">
                                <i class="fa fa-caret-right fa-rotate-90"></i>
                                %(name)s
                              </a>
                            </h4>
                          </div>
                          <div id="%(link)s" class="panel-collapse">
                            <div class="panel-body">

            """ % {
                "name": line[:-1],
                "link": line.replace(" ", "-").strip(":"),
            }
        elif "Layer" in line:
            detail += """</div>
                          </div>
                        </div>
                        <div class="panel panel-default">
                          <div class="panel-heading" role="tab">
                            <h4 class="panel-title">
                              <a class="packetHeader" data-target="#%(link)s">
                                <i class="fa fa-caret-right"></i>
                                %(name)s
                              </a>
                            </h4>
                          </div>
                          <div id="%(link)s" class="panel-collapse collapse">
                            <div class="panel-body">

            """ % {
                "name": line[:-1],
                "link": line.replace(" ", "-").strip(":"),
            }
        else:
            keyword = line.split(": ")[0] + ": "

            try:
                value = line.split(": ")[1]
            except IndexError:
                keyword = ""
                value = line

            try:
                keyword = keyword.split("= ")[1]
            except IndexError:
                pass

            detail += "<p><strong>%s</strong> %s</p>\n" % (keyword, value)

    detail += "</div></div></div>"
    return detail


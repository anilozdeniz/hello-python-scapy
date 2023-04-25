from scapy.all import *
from scapy.layers.http import *
import logging
import sys

# Set logging settings
logging.basicConfig(stream=sys.stdout, format='%(asctime)s - %(message)s', datefmt='%d-%b-%y %H:%M:%S', level=logging.INFO)
# global variable to store number of bytes
http_traffic_bytes = 0
# global dictionary for host key to number of visit value
host_to_visit = {}


def process_http_flows(pack):
    if pack.haslayer(HTTPRequest) or pack.haslayer(HTTPResponse):
        count_http_traffic_bytes(pack)
        count_http_host_visits(pack)
        return True
    else:
        return False


def count_http_traffic_bytes(pack):
    global http_traffic_bytes
    http_traffic_bytes += len(pack)


def count_http_host_visits(pack):
    global host_to_visit
    if pack.haslayer(HTTPRequest):
        # if this packet is an HTTP Request get the requested URL
        url = pack[HTTPRequest].Host.decode()
        # if key value pair exits increase the counter otherwise add the url key
        if url in host_to_visit:
            host_to_visit[url] += 1
        else:
            host_to_visit[url] = 1


def print_http_flows_count(packets):
    print("HTTP traffic flows: ", len(packets))


def print_http_traffic_bytes():
    print("HTTP traffic bytes: ", http_traffic_bytes)


def print_top_http_host_visit():
    # sort the dictionary with number of visit values descending order
    sorted_hosts = sorted(host_to_visit.items(), key=lambda x: x[1], reverse=True)
    # print the top visited host if any exists otherwise print N/A
    if not sorted_hosts:
        print("Top HTTP hostname: N/A")
    else:
        print("Top HTTP hostname: ", list(sorted_hosts[0])[0])


def main(arguments):
    logging.info('Start reading PCAP file')
    # sniff PCAP file, filter http flows and print number of http flows
    print_http_flows_count(sniff(offline=arguments[1], lfilter=process_http_flows))
    print_http_traffic_bytes()
    print_top_http_host_visit()
    logging.info('Finish processing PCAP file')


if __name__ == "__main__":
    main(sys.argv)

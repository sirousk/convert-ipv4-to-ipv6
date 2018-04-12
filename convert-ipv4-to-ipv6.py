#!/usr/bin/env python

""" Convert IPv4 pcap to IPv6.
"""
from scapy.all import *
import re, random

def header4to6 (ipheader):
  header6 = IPv6()
  header6.proto = ipheader.proto
  header6.src = gen_ipv6_header(ipheader.src)
  header6.dst = gen_ipv6_header(ipheader.dst)
  return header6

def convert_ipv4_to_ipv6 (pkt):
  ether = Ether(type=0x86DD, src=pkt.src, dst=pkt.dst)
  header6 = header4to6(pkt['IP'])
  if (pkt.haslayer('TCP')):
    newpkt = ether /header6 / pkt['TCP'] / pkt['TCP'].payload
  elif (pkt.haslayer('UDP')):
    newpkt = ether /header6 / pkt['UDP'] / pkt['UDP'].payload
  else:
    newpkt = ether/header6/pkt['IP'].payload;
  return newpkt;

IPs = {};
def gen_ipv6_header(baseIpv4=None):
  global IPs;
  if (baseIpv4):
    if (not baseIpv4 in IPs.keys()):
      IPs[baseIpv4] = "31::12:54:" + str(random.randint(10,99));
    return IPs[baseIpv4];
  else:
    return "31::12:54:" + str(random.randint(10,99));

if __name__ == "__main__":
  if (len(sys.argv) != 2):
    print "./convert-ipv4-to-ipv6.py <ipv4_pcap_file>";
    sys.exit(0);
  pkts = PcapReader(sys.argv[1]);
  file_name = (sys.argv[1].split("/")[-1]).split('.')[0]
  file_name +="-ipv6.pcap"
  for pkt in pkts:
    wrpcap(file_name, convert_ipv4_to_ipv6(pkt), append=True);
  print "Converted pcap file: " + file_name

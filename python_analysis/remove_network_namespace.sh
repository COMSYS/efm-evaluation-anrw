#!/bin/sh

# Use this https://unix.stackexchange.com/questions/272851/ip-netns-exec-command-execution-using-nsid-obtained-from-ip-netns-list-id
# to determine the network namespaces used by mininet

rm -f /var/run/netns/mininet_h1
rm -f /var/run/netns/mininet_h2
rm -f /var/run/netns/mininet_s1
rm -f /var/run/netns/mininet_s2
rm -f /var/run/netns/mininet_s3
#!/bin/sh

# Use this https://unix.stackexchange.com/questions/272851/ip-netns-exec-command-execution-using-nsid-obtained-from-ip-netns-list-id
# to determine the network namespaces used by mininet

# Create netns directory if it does not exist
mkdir -p /var/run/netns

h1=$(ps aux | grep "mininet:h1" | grep -v grep | awk {'print $2'})
h2=$(ps aux | grep "mininet:h2" | grep -v grep | awk {'print $2'})
s1=$(ps aux | grep "mininet:s1" | grep -v grep | awk {'print $2'})
s2=$(ps aux | grep "mininet:s2" | grep -v grep | awk {'print $2'})
s3=$(ps aux | grep "mininet:s3" | grep -v grep | awk {'print $2'})

ln -s /proc/$h1/ns/net /var/run/netns/mininet_h1
ln -s /proc/$h2/ns/net /var/run/netns/mininet_h2
ln -s /proc/$s1/ns/net /var/run/netns/mininet_s1
ln -s /proc/$s2/ns/net /var/run/netns/mininet_s2
ln -s /proc/$s3/ns/net /var/run/netns/mininet_s3
/*
    EFM Evaluation Framework
    Copyright (c) 2021 
	
	Author: Ike Kunze
	E-mail: kunze@comsys.rwth-aachen.de
*/
// This file implements our logic for deriving the packet loss groundtruth for our mininet experiments.

package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

/////////////////////////// TODOTODOTODOTODOTODOTODOTODOTODOTODOTODOTODOTODOTODOTODOTODOTODO
//// Rename output file names at the bottom and check where else they need to be changed

/*
./analyse_queueMonitor --queueMonitorFileName queue_monitor.txt --outputFileBaseName groundtruth.csv
*/

type preprocessPacketInfoCounter struct {
	packetMatches bool
	content       packetContent
	timestamp     time.Time
}

type PacketCount struct {
	timestamp    time.Time
	currentCount int
}

type packetContent struct {
	udp_data *layers.UDP
	srcIP    net.IP
	dstIP    net.IP
}

/* Function which checks if a given packet is a QUIC packet.
Returns a `preprocessPacketInfoCounter` struct which contains:
1. packetMatches: whether the packet is a QUIC packet
2. content: if packetMatches, the content of the udpLayer, as well as ip src/dst addresses
3. timestamp: the packet metadata timestamp
*/
func checkIfQuicPacketCounter(testPacket gopacket.Packet) preprocessPacketInfoCounter {

	if ipLayer := testPacket.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip_data, _ := ipLayer.(*layers.IPv4)

		if udpLayer := testPacket.Layer(layers.LayerTypeUDP); udpLayer != nil {

			udp_data, _ := udpLayer.(*layers.UDP)
			payload := udp_data.Payload

			// Check if the QUIC bit is set
			quic_bit := (payload[0]&64 == 64)

			// Process all QUIC packets, no matter whether they are short or long header packets
			if quic_bit {

				content := packetContent{
					udp_data: udp_data,
					srcIP:    ip_data.SrcIP,
					dstIP:    ip_data.DstIP,
				}

				packetInfo := preprocessPacketInfoCounter{
					packetMatches: true,
					content:       content,
					timestamp:     testPacket.Metadata().Timestamp,
				}
				return packetInfo

			} // QUIC Short Header
		} // UDP Layer

	} // IP Layer

	packetInfo := preprocessPacketInfoCounter{
		packetMatches: false,
	}
	return packetInfo

}

/*
This function counts the number of packets in s3_eth2_pcapname that have the given src (serverIP)/dst (clientIP) IP addresses.
*/
func derivePacketCounts(s3_eth2_pcapname string, clientIP net.IP, serverIP net.IP) []PacketCount {

	var simplisticCounter []PacketCount

	if s3_eth2_pcapname != "None" {

		if handle, err := pcap.OpenOffline(s3_eth2_pcapname); err != nil {
			panic(err)
		} else {

			packetCounter := 0
			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			for packet := range packetSource.Packets() {

				// Check if the current packet is a correct QUIC packet.
				packetInfo := checkIfQuicPacketCounter(packet)

				if packetInfo.packetMatches {
					// Check if the packet flows in the correct direction.
					if packetInfo.content.srcIP.Equal(serverIP) && packetInfo.content.dstIP.Equal(clientIP) {
						packetCounter += 1

						// Always store the current counter value together with a timestamp so that we can reason about the counter value at different points in time.
						currentCountValue := PacketCount{
							timestamp:    packet.Metadata().Timestamp,
							currentCount: packetCounter,
						}
						simplisticCounter = append(simplisticCounter, currentCountValue)
					}
				}
			}
		}
	}
	return simplisticCounter
}

type QueueingCalled struct {
	timestamp  time.Time
	loss_value int
}

/* Network Scenario:

				 Switch s3
h2 ----->   eth2  -------  eth1 -----> ....
			 ^               ^
             |  			 |
			 |  			 |
			 |               └── queueMonitor file to get dropped packets
			 |
		     └── pcap to count incoming packets
*/
func main() {

	fmt.Println("Start analysis of queue monitor information.")
	var queueMonitorFileName string
	var outputFileBaseName string
	var s3_eth2_pcapFile string

	flag.StringVar(&queueMonitorFileName, "queueMonitorFileName", "None", "Name of the queue monitor file")
	flag.StringVar(&outputFileBaseName, "outputFileBaseName", "None", "Outputfile Name")
	flag.StringVar(&s3_eth2_pcapFile, "s3_eth2_pcapFile", "None", "Name the pcap file for s3_eth2")
	flag.Parse()

	client_ip, _, _ := net.ParseCIDR("10.0.1.1/24")
	server_ip, _, _ := net.ParseCIDR("10.0.1.2/24")

	/*
		##### OUTPUT format of the queueMonitor file
		TIME(s)         dev                     drops           real_time
		4085365.42965   s3-eth1                 0               2021-06-10T14:12:34.795822Z
	*/

	inputFile, err := os.Open(queueMonitorFileName)
	if err != nil {
		panic(err)
	}
	defer inputFile.Close()

	scanner := bufio.NewScanner(inputFile)

	// Keep track for each interface.
	var measurements_clientswitch []QueueingCalled
	var measurements_switchserver []QueueingCalled
	var measurements_serverswitch []QueueingCalled
	var measurements_switchclient []QueueingCalled

	for scanner.Scan() {

		var currentLine = string(scanner.Text())

		// Skip header line (TIME(s)         dev                     drops           real_time)
		if strings.HasPrefix(currentLine, "TIME") {

		} else {
			if !strings.HasPrefix(currentLine, "\n") {

				var elements = strings.Fields(currentLine)

				if len(elements) > 0 {

					// Line Format: 		4085365.42965   s3-eth1                 0               2021-06-10T14:12:34.795822Z

					var device = elements[1]
					var packet_drops, _ = strconv.ParseInt(elements[2], 10, 32)

					timeStampLayout := "2006-01-02T15:04:05.9Z"

					parsedDate, err := time.Parse(timeStampLayout, elements[3])
					if err != nil {
						fmt.Println("error: %v", err)
					}

					measurement := QueueingCalled{
						timestamp:  parsedDate,
						loss_value: int(packet_drops),
					}

					// Assign the extracted drop count to the correct interface
					if device == "s1-eth1" {
						measurements_clientswitch = append(measurements_clientswitch, measurement)
					} else if device == "s1-eth2" {
						measurements_switchclient = append(measurements_switchclient, measurement)
					} else if device == "s3-eth1" {
						measurements_switchserver = append(measurements_switchserver, measurement)
					} else if device == "s3-eth2" {
						measurements_serverswitch = append(measurements_serverswitch, measurement)
					}
				}
			}
		}
	}

	// Write observed number of packet drops to file for each interface
	if outputFile, err := os.Create(outputFileBaseName + "groundtruth_loss_clientswitch.csv"); err == nil {
		for _, measurement := range measurements_clientswitch {
			outputFile.WriteString(fmt.Sprintf("%-s,%-d\n", measurement.timestamp, measurement.loss_value))
		}
	} else {
		fmt.Println(err)
	}

	if outputFile, err := os.Create(outputFileBaseName + "groundtruth_loss_switchclient.csv"); err == nil {

		for _, measurement := range measurements_switchclient {
			outputFile.WriteString(fmt.Sprintf("%-s,%-d\n", measurement.timestamp, measurement.loss_value))
		}

	} else {
		fmt.Println(err)
	}

	if outputFile, err := os.Create(outputFileBaseName + "groundtruth_loss_switchserver.csv"); err == nil {

		for _, measurement := range measurements_switchserver {
			outputFile.WriteString(fmt.Sprintf("%-s,%-d\n", measurement.timestamp, measurement.loss_value))
		}

	} else {
		fmt.Println(err)
	}

	if outputFile, err := os.Create(outputFileBaseName + "groundtruth_loss_serverswitch.csv"); err == nil {

		for _, measurement := range measurements_serverswitch {
			outputFile.WriteString(fmt.Sprintf("%-s,%-d\n", measurement.timestamp, measurement.loss_value))
		}

	} else {
		fmt.Println(err)
	}

	/* For our paper, we focussed on packet drops on particular outbound interface.
	   Thus, also derive the ground truth of packets that have entered the device before being dropped using the pcap File of the inbound interface.
	   Then, write both parts of the information for this particular interface to a file.
	*/

	packetCounts := derivePacketCounts(s3_eth2_pcapFile, client_ip, server_ip)

	if outputFile, err := os.Create(outputFileBaseName + "groundtruth_overall_packets_and_loss_count.csv"); err == nil {

		for _, measurement := range measurements_switchserver {
			outputFile.WriteString(fmt.Sprintf("losscount,%-s,%-d\n", measurement.timestamp, measurement.loss_value))
		}

		for _, measurement := range packetCounts {
			outputFile.WriteString(fmt.Sprintf("overallcount,%-s,%-d\n", measurement.timestamp, measurement.currentCount))
		}
	} else {
		fmt.Println(err)
	}
}

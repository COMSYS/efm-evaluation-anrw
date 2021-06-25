/*
    EFM Evaluation Framework
    Copyright (c) 2021 
	
	Author: Ike Kunze
	E-mail: kunze@comsys.rwth-aachen.de
*/
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type BurstFinished struct {
	timestamp  time.Time
	burst_size int
}

func main() {

	fmt.Println("Analyze loss burst sizes.")
	var queueMonitorFileName string
	var outputFileBaseName string

	flag.StringVar(&queueMonitorFileName, "queueMonitorFileName", "None", "Full path of the file")
	flag.StringVar(&outputFileBaseName, "outputFileBaseName", "None", "Basename of the output file to be analyzed")
	flag.Parse()

	/*
		TIME(s)       	dev                  	drops     	real_time
		3053048.66199 	s3-eth1              	10        	2021-05-20T15:33:06.688819Z
		3053048.66342 	s3-eth1              	10        	2021-05-20T15:33:06.690248Z
		3053048.66447 	s3-eth1              	10        	2021-05-20T15:33:06.691302Z
		3053048.66586 	s3-eth1              	10        	2021-05-20T15:33:06.692691Z
	*/

	inputFile, err := os.Open(queueMonitorFileName)
	if err != nil {
		panic(err)
	}
	defer inputFile.Close()

	scanner := bufio.NewScanner(inputFile)

	var measurements_clientswitch []BurstFinished
	var measurements_switchserver []BurstFinished
	var measurements_serverswitch []BurstFinished
	var measurements_switchclient []BurstFinished

	current_burst_size_s3_eth1 := int64(0)
	previous_loss_count_s3_eth1 := int64(0)
	s3_eth1_reported := false
	current_burst_size_s3_eth2 := int64(0)
	previous_loss_count_s3_eth2 := int64(0)
	s3_eth2_reported := false
	current_burst_size_s1_eth1 := int64(0)
	previous_loss_count_s1_eth1 := int64(0)
	s1_eth1_reported := false
	current_burst_size_s1_eth2 := int64(0)
	previous_loss_count_s1_eth2 := int64(0)
	s1_eth2_reported := false

	for scanner.Scan() {

		var currentLine = string(scanner.Text())

		if strings.HasPrefix(currentLine, "TIME") {
		} else {
			if !strings.HasPrefix(currentLine, "\n") {

				var elements = strings.Fields(currentLine)

				if len(elements) > 0 {

					var device = elements[1]

					var packet_drops, _ = strconv.ParseInt(elements[2], 10, 32)

					timeStampLayout := "2006-01-02T15:04:05.9Z"

					parsedDate, err := time.Parse(timeStampLayout, elements[3])
					if err != nil {
						fmt.Println("error: %v", err)
					}

					if device == "s1-eth1" {

						if packet_drops > 0 {

							if packet_drops > previous_loss_count_s1_eth1 {
								current_burst_size_s1_eth1 += 1
								previous_loss_count_s1_eth1 = packet_drops
								s1_eth1_reported = false
							} else {

								if !s1_eth1_reported {
									measurement := BurstFinished{
										timestamp:  parsedDate,
										burst_size: int(current_burst_size_s1_eth1),
									}
									measurements_clientswitch = append(measurements_clientswitch, measurement)
									current_burst_size_s1_eth1 = 0
									s1_eth1_reported = true
								}
							}
						}
					} else if device == "s1-eth2" {
						if packet_drops > 0 {

							if packet_drops > previous_loss_count_s1_eth2 {
								current_burst_size_s1_eth2 += 1
								previous_loss_count_s1_eth2 = packet_drops
								s1_eth2_reported = false
							} else {

								if !s1_eth2_reported {
									measurement := BurstFinished{
										timestamp:  parsedDate,
										burst_size: int(current_burst_size_s1_eth2),
									}
									measurements_switchclient = append(measurements_switchclient, measurement)
									current_burst_size_s1_eth2 = 0
									s1_eth2_reported = true
								}
							}
						}
					} else if device == "s3-eth1" {
						if packet_drops > 0 {

							if packet_drops > previous_loss_count_s3_eth1 {
								current_burst_size_s3_eth1 += 1
								previous_loss_count_s3_eth1 = packet_drops
								s3_eth1_reported = false
							} else {

								if !s3_eth1_reported {
									measurement := BurstFinished{
										timestamp:  parsedDate,
										burst_size: int(current_burst_size_s3_eth1),
									}
									measurements_switchserver = append(measurements_switchserver, measurement)
									current_burst_size_s3_eth1 = 0
									s3_eth1_reported = true
								}
							}
						}
					} else if device == "s3-eth2" {
						if packet_drops > 0 {

							if packet_drops > previous_loss_count_s3_eth2 {
								current_burst_size_s3_eth2 += 1
								previous_loss_count_s3_eth2 = packet_drops
								s3_eth2_reported = false
							} else {

								if !s3_eth2_reported {
									measurement := BurstFinished{
										timestamp:  parsedDate,
										burst_size: int(current_burst_size_s3_eth2),
									}
									measurements_serverswitch = append(measurements_serverswitch, measurement)
									current_burst_size_s3_eth2 = 0
									s3_eth2_reported = true
								}
							}
						}
					}
				}
			}
		}
	}

	if outputFile, err := os.Create(outputFileBaseName + "burst_sizes_switchserver.csv"); err == nil {

		overall_burst_size := 0
		number_of_bursts := 0
		var bursts_over_64 []int

		for _, measurement := range measurements_switchserver {
			outputFile.WriteString(fmt.Sprintf("%-s,%-d\n", measurement.timestamp, measurement.burst_size))
			overall_burst_size += measurement.burst_size
			number_of_bursts += 1
			if measurement.burst_size >= 64 {
				bursts_over_64 = append(bursts_over_64, measurement.burst_size)
			}
		}
		if number_of_bursts == 0 {
			outputFile.WriteString("No Bursts")
		} else {
			outputFile.WriteString(fmt.Sprintf("Overall Burst Size: %-d, Number of Bursts: %-d, Average Burst Size: %-d", overall_burst_size, number_of_bursts, overall_burst_size/number_of_bursts))
		}
		count := 0
		max_burst := 0
		for _, burst := range bursts_over_64 {
			outputFile.WriteString(fmt.Sprintf("Burst Size: %-d\n", burst))
			count += 1
			if burst > max_burst {
				max_burst = burst
			}
		}
		outputFile.WriteString(fmt.Sprintf("Bursts > 64: %-d, Max Burst: %-d\n", count, max_burst))

	} else {
		fmt.Println(err)
	}
}

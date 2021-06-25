/*
    EFM Evaluation Framework
    Copyright (c) 2021 
	
	Author: Ike Kunze
	E-mail: kunze@comsys.rwth-aachen.de
*/

package main

import (
	"flag"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"os"
)

type BitPosition int

const (
	SpinBitPosition BitPosition = iota
	ExtensionBit1Position
	ExtensionBit2Position
	ExtensionBit3Position
	ExtensionBit4Position
	ExtensionByteBit1Position
	ExtensionByteBit2Position
	ExtensionByteBit3Position
	ExtensionByteBit4Position
)

type extensionBits struct {
	spin_bit_value           int
	extensionbit1_value      int
	extensionbit2_value      int
	extensionbit3_value      int
	extensionbit4_value      int
	extensionbyte2bit1_value int
	extensionbyte2bit2_value int
	extensionbyte2bit3_value int
	extensionbyte2bit4_value int
}

type addressInfo struct {
	srcIP   string
	dstIP   string
	srcPort int
	dstPort int
}

type preprocessPacketInfo struct {
	packetMatches bool
	addresses     addressInfo
	bitValues     extensionBits
	bitValuesMap  map[BitPosition]int
}

/* Function which checks if a given packet is a QUIC packet.
Returns a `preprocessPacketInfo` struct.
*/
func checkIfQuicPacket(testPacket gopacket.Packet, sourceIP net.IP) preprocessPacketInfo {

	debug := false

	if ipLayer := testPacket.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip_data, _ := ipLayer.(*layers.IPv4)

		if ip_data.SrcIP.Equal(sourceIP) {

			if udpLayer := testPacket.Layer(layers.LayerTypeUDP); udpLayer != nil {

				udp_data, _ := udpLayer.(*layers.UDP)
				payload := udp_data.Payload

				payload_offset := 0
				end_reached := false

				for !end_reached {

					long_header := (payload[payload_offset]&128 == 128)
					quic_bit := (payload[payload_offset]&64 == 64)

					if !quic_bit {
						end_reached = true

					} else {

						// Distinguish between long and short header
						// Long header is relevant if there are short header packets mixed in the same datagram
						if long_header {

							packet_type := int((payload[payload_offset] & 0x30) / 16)
							payload_offset = payload_offset + 5
							dcil := payload[payload_offset] // Determine Destination Connection ID Length & Skip it
							payload_offset = payload_offset + int(dcil) + 1
							scil := payload[payload_offset] // Determine Source Connection ID Length & Skip it
							payload_offset = payload_offset + int(scil) + 1

							//Determine length of remaining packet
							// Initial packet, a token length follows next
							if packet_type == 0 {

								token_length := payload[payload_offset]
								payload_offset = payload_offset + int(token_length) + 1

								// Don't handle retry packets
							} else if packet_type == 3 {
								fmt.Println("There's a retry packet.")
							}

							// Length encoded using variable-length integer encoding (see QUIC RFC)

							// First get length of variable length encoding
							encoding_prefix := payload[payload_offset] >> 6
							encoding_length := 1 << encoding_prefix

							var length int
							if encoding_length == 1 {
								length = int(payload[payload_offset] & 0x3f)
							}
							if encoding_length == 2 {
								length = (int(payload[payload_offset]&0x3f) << 8) + int(payload[payload_offset+1])
							}
							if encoding_length > 4 {
								fmt.Println("Longer encodings currently not supported (but also not needed for the experiments).")
							}

							if payload_offset+2+length != len(payload) {
								payload_offset = payload_offset + 2 + length
							} else {
								end_reached = true
							}

							// We have a short header
						} else {

							if debug {
								fmt.Println("We might have valid QUIC traffic with a short header. Use this packet")
							}

							spin_bit := 0
							if payload[payload_offset]&0x20 == 0x20 {
								spin_bit = 1
							}

							extension_bit1 := 0
							if payload[payload_offset]&0x10 == 0x10 {
								extension_bit1 = 1
							}

							extension_bit2 := 0
							if payload[payload_offset]&0x08 == 0x08 {
								extension_bit2 = 1
							}

							extension_bit3 := 0
							if payload[payload_offset]&0x04 == 0x04 {
								extension_bit3 = 1
							}

							extension_bit4 := 0
							if payload[payload_offset]&0x02 == 0x02 {
								extension_bit4 = 1
							}

							extensionbyte2bit1 := 0
							if payload[payload_offset+1]&0x80 == 0x80 {
								extensionbyte2bit1 = 1
							}

							extensionbyte2bit2 := 0
							if payload[payload_offset+1]&0x40 == 0x40 {
								extensionbyte2bit2 = 1
							}

							extensionbyte2bit3 := 0
							if payload[payload_offset+1]&0x20 == 0x20 {
								extensionbyte2bit3 = 1
							}

							extensionbyte2bit4 := 0
							if payload[payload_offset+1]&0x10 == 0x10 {
								extensionbyte2bit4 = 1
							}

							bitValues := extensionBits{
								spin_bit_value:           spin_bit,
								extensionbit1_value:      extension_bit1,
								extensionbit2_value:      extension_bit2,
								extensionbit3_value:      extension_bit3,
								extensionbit4_value:      extension_bit4,
								extensionbyte2bit1_value: extensionbyte2bit1,
								extensionbyte2bit2_value: extensionbyte2bit2,
								extensionbyte2bit3_value: extensionbyte2bit3,
								extensionbyte2bit4_value: extensionbyte2bit4,
							}

							addresses := addressInfo{
								srcIP:   ip_data.SrcIP.String(),
								dstIP:   ip_data.DstIP.String(),
								srcPort: int(udp_data.SrcPort),
								dstPort: int(udp_data.DstPort),
							}

							bitValuesMap := map[BitPosition]int{SpinBitPosition: spin_bit,
								ExtensionBit1Position:     extension_bit1,
								ExtensionBit2Position:     extension_bit2,
								ExtensionBit3Position:     extension_bit3,
								ExtensionBit4Position:     extension_bit4,
								ExtensionByteBit1Position: extensionbyte2bit1,
								ExtensionByteBit2Position: extensionbyte2bit2,
								ExtensionByteBit3Position: extensionbyte2bit3,
								ExtensionByteBit4Position: extensionbyte2bit4}

							packetInfo := preprocessPacketInfo{
								packetMatches: true,
								addresses:     addresses,
								bitValues:     bitValues,
								bitValuesMap:  bitValuesMap,
							}

							return packetInfo

						} // QUIC Short Header
					} // QUIC Packet
				}
			} // UDP Layer
		} // IP address check
	} // IP Layer

	packetInfo := preprocessPacketInfo{
		packetMatches: false,
	}
	return packetInfo

}

/*
Observer logic for the L-Bit
*/

type l_loss_event_bit_measurement struct {
	timestamp      time.Time
	loss_event_bit bool
}

func analyzeOneDirectionalPcap_L_Loss_Event_Bit(pcap_name string, sourceIP net.IP, lossbit_position BitPosition) map[string][]l_loss_event_bit_measurement {

	l_loss_event_bit_flows_measurements := make(map[string][]l_loss_event_bit_measurement)

	debug := false

	if pcap_name != "None" {

		if handle, err := pcap.OpenOffline(pcap_name); err != nil {
			panic(err)
		} else {

			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			for packet := range packetSource.Packets() {

				packetInfo := checkIfQuicPacket(packet, sourceIP)

				if packetInfo.packetMatches {

					// Identify flows based on src/dst IP/ports
					flow_identifier := packetInfo.addresses.srcIP + "-" + packetInfo.addresses.dstIP + "-" + strconv.Itoa(packetInfo.addresses.srcPort) + "-" + strconv.Itoa(packetInfo.addresses.dstPort)

					if debug {
						fmt.Println(flow_identifier)
						fmt.Println(packet.Metadata().Timestamp)
					}

					// Flow is already tracked
					if _, found := l_loss_event_bit_flows_measurements[flow_identifier]; found {

						if debug {
							fmt.Println("--")
							fmt.Println(packetInfo.addresses.srcIP, packetInfo.addresses.dstIP)
							fmt.Println(packet.Metadata().Timestamp)
						}

						loss_event := false
						if packetInfo.bitValuesMap[lossbit_position] == 1 {
							loss_event = true
						}

						new_measurement := l_loss_event_bit_measurement{
							timestamp:      packet.Metadata().Timestamp,
							loss_event_bit: loss_event,
						}

						l_loss_event_bit_flows_measurements[flow_identifier] = append(l_loss_event_bit_flows_measurements[flow_identifier], new_measurement)

						// Flow is not in the table.
					} else {

						loss_event := false
						if packetInfo.bitValuesMap[lossbit_position] == 1 {
							loss_event = true
						}

						new_measurement := l_loss_event_bit_measurement{
							timestamp:      packet.Metadata().Timestamp,
							loss_event_bit: loss_event,
						}
						l_loss_event_bit_flows_measurements[flow_identifier] = append(l_loss_event_bit_flows_measurements[flow_identifier], new_measurement)
					}
				}
			}
		}
	}
	return l_loss_event_bit_flows_measurements
}

/*
Observer logic for the T-Bit.
*/

type T_Bit_Phase int

const (
	PhaseGeneration T_Bit_Phase = iota
	PhaseReflection
)

func (phase T_Bit_Phase) GetNextPhase() T_Bit_Phase {

	return phase + 1
}

func (phase T_Bit_Phase) String() string {
	return [...]string{"Phase1", "Phase2"}[phase]
}

type t_round_trip_loss_bit_flow_information struct {
	identifier     string
	spin_bit_value int

	currentCycleEmpty   bool
	current_counter     int
	prev_counter        int
	in_reflection_phase bool

	intermediate_measurement t_round_trip_loss_bit_measurement
}

type t_round_trip_loss_bit_measurement struct {
	startTime time.Time
	endTime   time.Time

	phase_counts map[T_Bit_Phase]int
}

func analyzeOneDirectionalPcap_T_Round_Trip_Loss_Bit(pcap_name string, sourceIP net.IP, spinbit_position BitPosition, t_bit_position BitPosition) map[string][]t_round_trip_loss_bit_measurement {

	t_round_trip_loss_bit_flows := make(map[string]t_round_trip_loss_bit_flow_information)
	t_round_trip_loss_bit_flows_measurements := make(map[string][]t_round_trip_loss_bit_measurement)

	if pcap_name != "None" {

		if handle, err := pcap.OpenOffline(pcap_name); err != nil {
			panic(err)
		} else {

			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			for packet := range packetSource.Packets() {

				packetInfo := checkIfQuicPacket(packet, sourceIP)

				if packetInfo.packetMatches {

					flow_identifier := packetInfo.addresses.srcIP + "-" + packetInfo.addresses.dstIP + "-" + strconv.Itoa(packetInfo.addresses.srcPort) + "-" + strconv.Itoa(packetInfo.addresses.dstPort)

					if trackedFlow, found := t_round_trip_loss_bit_flows[flow_identifier]; found {

						// Spin has changed, advance phase
						if trackedFlow.spin_bit_value != packetInfo.bitValuesMap[spinbit_position] {

							trackedFlow.spin_bit_value = packetInfo.bitValuesMap[spinbit_position]

							// Stop phase once the current cycle was empty
							if trackedFlow.currentCycleEmpty {

								if trackedFlow.current_counter > 0 {
									// If we are in the reflection phase, store the output
									if trackedFlow.in_reflection_phase {

										//We are in a correct reflection phase
										if trackedFlow.current_counter <= trackedFlow.prev_counter {

											// Store completed measurement
											trackedFlow.intermediate_measurement.endTime = packet.Metadata().Timestamp

											trackedFlow.intermediate_measurement.phase_counts[PhaseGeneration] = trackedFlow.prev_counter
											trackedFlow.intermediate_measurement.phase_counts[PhaseReflection] = trackedFlow.current_counter

											t_round_trip_loss_bit_flows_measurements[flow_identifier] = append(t_round_trip_loss_bit_flows_measurements[flow_identifier], trackedFlow.intermediate_measurement)

											// And set up new measurement
											new_measurement := t_round_trip_loss_bit_measurement{
												startTime:    packet.Metadata().Timestamp,
												endTime:      packet.Metadata().Timestamp,
												phase_counts: map[T_Bit_Phase]int{PhaseGeneration: 0, PhaseReflection: 0},
											}

											// Reset tracked flow
											trackedFlow.intermediate_measurement = new_measurement

											// Resynchronize phases
										} else {

											trackedFlow.prev_counter = trackedFlow.current_counter
											trackedFlow.in_reflection_phase = false

										}
									}
									trackedFlow.prev_counter = trackedFlow.current_counter
									trackedFlow.current_counter = 0
									trackedFlow.in_reflection_phase = !trackedFlow.in_reflection_phase
								}
							}
							trackedFlow.currentCycleEmpty = true
						}

						// No matter what the spin value says, add to the current counter if T bit is set
						if packetInfo.bitValuesMap[t_bit_position] == 1 {
							trackedFlow.current_counter = trackedFlow.current_counter + 1
							trackedFlow.currentCycleEmpty = false
						}

						t_round_trip_loss_bit_flows[flow_identifier] = trackedFlow

						// Flow is not in the table.
					} else {

						new_measurement := t_round_trip_loss_bit_measurement{
							startTime:    packet.Metadata().Timestamp,
							endTime:      packet.Metadata().Timestamp,
							phase_counts: map[T_Bit_Phase]int{PhaseGeneration: 0, PhaseReflection: 0},
						}

						observed_flow := t_round_trip_loss_bit_flow_information{
							identifier:          flow_identifier,
							spin_bit_value:      packetInfo.bitValuesMap[spinbit_position],
							currentCycleEmpty:   true,
							in_reflection_phase: false,

							current_counter:          0,
							prev_counter:             0,
							intermediate_measurement: new_measurement,
						}

						if packetInfo.bitValuesMap[t_bit_position] == 1 {
							observed_flow.current_counter = observed_flow.current_counter + 1
							observed_flow.currentCycleEmpty = false
						}

						t_round_trip_loss_bit_flows[flow_identifier] = observed_flow
					}
				}
			}
		}
	}
	return t_round_trip_loss_bit_flows_measurements
}

/*
Observer logic for the Q-Bit.
*/

type Q_Bit_Phase int

const (
	// Square wave phase 0 -> values are 0
	QPhase0 Q_Bit_Phase = iota
	// Square wave phase 1 -> values are 1
	QPhase1
)

func (phase Q_Bit_Phase) String() string {
	return [...]string{"Phase0", "Phase1"}[phase]
}

type q_square_bit_flow_information struct {
	identifier                string
	q_square_bit_value        int
	current_period_count      int
	current_threshold_counter int

	startTime time.Time
}

type q_square_bit_measurement struct {
	startTime             time.Time
	endTime               time.Time
	phase_value           int
	phase_count           int
	nominal_period_length int
	nominal_x_value       int
}

// Use a fixed reordering threshold of 8
var SquareThreshold = 8

func analyzeOneDirectionalPcap_Q_Square_Bit(pcap_name string, sourceIP net.IP, q_bit_position BitPosition) map[string][]q_square_bit_measurement {

	q_square_bit_flows := make(map[string]q_square_bit_flow_information)
	q_square_bit_flows_measurements := make(map[string][]q_square_bit_measurement)

	debug := false

	// Use a square period of 64
	square_period_N := 64
	marking_block_threshold_X := 0 // not used

	if pcap_name != "None" {

		if handle, err := pcap.OpenOffline(pcap_name); err != nil {
			panic(err)
		} else {

			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			for packet := range packetSource.Packets() {

				packetInfo := checkIfQuicPacket(packet, sourceIP)

				if packetInfo.packetMatches {

					flow_identifier := packetInfo.addresses.srcIP + "-" + packetInfo.addresses.dstIP + "-" + strconv.Itoa(packetInfo.addresses.srcPort) + "-" + strconv.Itoa(packetInfo.addresses.dstPort)

					if debug {
						fmt.Println(flow_identifier)
						fmt.Println(packet.Metadata().Timestamp)
					}

					// Flow is in the identification table
					if trackedFlow, found := q_square_bit_flows[flow_identifier]; found {

						if debug {
							fmt.Println("--")
							fmt.Println(packetInfo.addresses.srcIP, packetInfo.addresses.dstIP)
							fmt.Println(packet.Metadata().Timestamp)
						}

						// We have a change in the square bit
						if trackedFlow.q_square_bit_value != packetInfo.bitValuesMap[q_bit_position] {

							// Protect against reordering using a threshold as suggested in the draft
							trackedFlow.current_threshold_counter += 1

							// Threshold has been passed, do the change
							if trackedFlow.current_threshold_counter == SquareThreshold {

								// We should actually distinguish these cases, but currently we do the same thing for all of them
								new_measurement := q_square_bit_measurement{
									startTime:             trackedFlow.startTime,
									endTime:               packet.Metadata().Timestamp,
									phase_value:           trackedFlow.q_square_bit_value,
									phase_count:           trackedFlow.current_period_count,
									nominal_period_length: square_period_N,
									nominal_x_value:       marking_block_threshold_X,
								}

								// Append the measurement
								q_square_bit_flows_measurements[flow_identifier] = append(q_square_bit_flows_measurements[flow_identifier], new_measurement)

								// The count corresponds exactly to the considered square period length
								// Flush the measurement and start the new period
								if trackedFlow.current_period_count == square_period_N {

									// There were too few signals in the current period, but that could be due to loss
								} else if trackedFlow.current_period_count < square_period_N {

									// There were too many signals... this should not happen
								} else {
									fmt.Println("Square Bit: Too many signals...")

								}

								trackedFlow.q_square_bit_value = packetInfo.bitValuesMap[q_bit_position]
								trackedFlow.startTime = packet.Metadata().Timestamp
								trackedFlow.current_period_count = SquareThreshold
								trackedFlow.current_threshold_counter = 0
							}
							q_square_bit_flows[flow_identifier] = trackedFlow

							// Value has not change. Simply increase the counter
						} else {
							trackedFlow.current_period_count += 1
							q_square_bit_flows[flow_identifier] = trackedFlow
						}

						// Flow is not in the table.
					} else {

						// Setup new measurement
						observed_flow := q_square_bit_flow_information{
							identifier:                flow_identifier,
							q_square_bit_value:        packetInfo.bitValuesMap[q_bit_position],
							current_period_count:      1,
							startTime:                 packet.Metadata().Timestamp,
							current_threshold_counter: 0,
						}

						q_square_bit_flows[flow_identifier] = observed_flow

					} // tracked flow not in table
				} // if packet matches
			} // for packet
		} // pcap open offline
	} // pcap file name
	return q_square_bit_flows_measurements
}

/*

Observer Logic for the R-Bit.

*/

type R_Bit_Phase int

const (
	RPhaseStartup R_Bit_Phase = iota
	// Square wave phase 0 -> values are 0
	RPhase0
	// Square wave phase 1 -> values are 1
	RPhase1
)

func (phase R_Bit_Phase) String() string {
	return [...]string{"Start", "Phase0", "Phase1"}[phase]
}

type r_reflection_square_bit_flow_information struct {
	identifier                    string
	r_reflection_square_bit_value int
	current_period_count          int
	current_threshold_counter     int

	phase_name R_Bit_Phase
	startTime  time.Time
}

type r_reflection_square_bit_measurement struct {
	startTime time.Time
	endTime   time.Time

	phase_value           int
	phase_count           int
	nominal_period_length int
	nominal_x_value       int
}

func analyzeOneDirectionalPcap_R_Reflection_Square_Bit(pcap_name string, sourceIP net.IP, r_bit_position BitPosition, q_bit_position BitPosition) map[string][]r_reflection_square_bit_measurement {

	r_reflection_square_bit_flows := make(map[string]r_reflection_square_bit_flow_information)
	r_reflection_square_bit_flows_measurements := make(map[string][]r_reflection_square_bit_measurement)

	debug := false

	// Use square period of 64
	square_period_N := 64
	marking_block_threshold_X := 0 // not used

	if pcap_name != "None" {

		if handle, err := pcap.OpenOffline(pcap_name); err != nil {
			panic(err)
		} else {

			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			for packet := range packetSource.Packets() {

				packetInfo := checkIfQuicPacket(packet, sourceIP)

				if packetInfo.packetMatches {

					flow_identifier := packetInfo.addresses.srcIP + "-" + packetInfo.addresses.dstIP + "-" + strconv.Itoa(packetInfo.addresses.srcPort) + "-" + strconv.Itoa(packetInfo.addresses.dstPort)

					if debug {
						fmt.Println(flow_identifier)
						fmt.Println(packet.Metadata().Timestamp)
					}

					// Flow is in the identification table
					if trackedFlow, found := r_reflection_square_bit_flows[flow_identifier]; found {

						if debug {
							fmt.Println("--")
							fmt.Println(packetInfo.addresses.srcIP, packetInfo.addresses.dstIP)
							fmt.Println(packet.Metadata().Timestamp)
						}

						// We have a change in the reflection square bit
						if trackedFlow.r_reflection_square_bit_value != packetInfo.bitValuesMap[r_bit_position] {

							// Protect against reordering using a threshold as suggested in the draft
							trackedFlow.current_threshold_counter += 1

							// Threshold has been passed, do the change
							if trackedFlow.current_threshold_counter == SquareThreshold {

								// In this case, only transition to the next phase, but don't collect a measurement as the initial 0 period is idling
								if trackedFlow.phase_name == RPhaseStartup {

									// Store the measurement
								} else {

									// We should actually distinguish these cases, but currently we do the same thing for all of them
									new_measurement := r_reflection_square_bit_measurement{
										startTime:             trackedFlow.startTime,
										endTime:               packet.Metadata().Timestamp,
										phase_value:           trackedFlow.r_reflection_square_bit_value,
										phase_count:           trackedFlow.current_period_count,
										nominal_period_length: square_period_N,
										nominal_x_value:       marking_block_threshold_X,
									}

									// Append the measurement
									r_reflection_square_bit_flows_measurements[flow_identifier] = append(r_reflection_square_bit_flows_measurements[flow_identifier], new_measurement)
								}

								// The count corresponds exactly to the considered square period length
								// Flush the measurement and start the new period
								if trackedFlow.current_period_count == square_period_N {

									// There were too few signals in the current period, but that could be due to loss
								} else if trackedFlow.current_period_count < square_period_N {

									// There were too many signals... this should not happen
								} else {
									fmt.Println("Reflection Bit: Too many signals...")

								}

								trackedFlow.r_reflection_square_bit_value = packetInfo.bitValuesMap[r_bit_position]
								trackedFlow.startTime = packet.Metadata().Timestamp
								trackedFlow.current_period_count = SquareThreshold
								trackedFlow.current_threshold_counter = 0
								if packetInfo.bitValuesMap[r_bit_position] == 1 {
									trackedFlow.phase_name = RPhase1
								} else {
									trackedFlow.phase_name = RPhase0
								}
							}
							r_reflection_square_bit_flows[flow_identifier] = trackedFlow

							// Value has not change. Simply increase the counter
						} else {

							trackedFlow.current_period_count += 1
							r_reflection_square_bit_flows[flow_identifier] = trackedFlow
						}

						// Flow is not in the table.
					} else {

						if packetInfo.bitValuesMap[r_bit_position] == 1 {
							trackedFlow.phase_name = RPhase1
						} else {
							trackedFlow.phase_name = RPhaseStartup
						}

						// Setup new measurement
						observed_flow := r_reflection_square_bit_flow_information{
							identifier:                    flow_identifier,
							r_reflection_square_bit_value: packetInfo.bitValuesMap[r_bit_position],
							current_period_count:          1,
							startTime:                     packet.Metadata().Timestamp,
							current_threshold_counter:     0,
						}

						r_reflection_square_bit_flows[flow_identifier] = observed_flow

					} // tracked flow not in table
				} // if packet matches
			} // for packet
		} // pcap open offline
	} // pcap file name
	return r_reflection_square_bit_flows_measurements
}

func main() {

	fmt.Println("Start analysis of .pcap files.")

	var s2_eth1_pcapFile string
	var s2_eth2_pcapFile string
	var outputFileBaseName string
	var measurement_techniques int

	flag.StringVar(&s2_eth1_pcapFile, "s2_eth1_pcapFile", "None", "Name of first pcap file to be analyzed")
	flag.StringVar(&s2_eth2_pcapFile, "s2_eth2_pcapFile", "None", "Name of second pcap file to be analyzed")
	flag.StringVar(&outputFileBaseName, "outputFileBaseName", "None", "Basename of the output file to be analyzed")
	flag.IntVar(&measurement_techniques, "measurement_techniques", 0, "Which measurement techniques should be analyzed? Use 42 for all.")
	flag.Parse()

	/*
		measurement_techniques == 42: all measurement techniques
		measurement_techniques == 43: loss measurement techniques
	*/

	ip_1, _, _ := net.ParseCIDR("10.0.1.1/24")
	ip_2, _, _ := net.ParseCIDR("10.0.1.2/24")

	if measurement_techniques == 42 || measurement_techniques == 43 {
		fmt.Println("Perform L Loss Event Bit Analysis")
		l_loss_event_bit_flows_measurements_direction1 := analyzeOneDirectionalPcap_L_Loss_Event_Bit(s2_eth1_pcapFile, ip_1, ExtensionByteBit3Position)
		l_loss_event_bit_flows_measurements_direction2 := analyzeOneDirectionalPcap_L_Loss_Event_Bit(s2_eth2_pcapFile, ip_2, ExtensionByteBit3Position)

		if outputFile, err := os.Create(outputFileBaseName + "lbit.csv"); err == nil {

			for flow_id, measurements := range l_loss_event_bit_flows_measurements_direction1 {
				for _, measurement := range measurements {
					outputFile.WriteString(fmt.Sprintf("%-s,%-s,%-t\n", flow_id, measurement.timestamp.String(), measurement.loss_event_bit))
				}
			}

			for flow_id, measurements := range l_loss_event_bit_flows_measurements_direction2 {
				for _, measurement := range measurements {
					outputFile.WriteString(fmt.Sprintf("%-s,%-s,%-t\n", flow_id, measurement.timestamp.String(), measurement.loss_event_bit))
				}
			}

		} else {
			fmt.Println(err)
		}

	} else {
		fmt.Println("Skip L Loss Event Bit Analysis")
	}

	if measurement_techniques == 42 || measurement_techniques == 43 {
		fmt.Println("Perform T Round Trip Loss Bit Analysis")
		t_round_trip_loss_bit_flows_measurements_direction1 := analyzeOneDirectionalPcap_T_Round_Trip_Loss_Bit(s2_eth1_pcapFile, ip_1, SpinBitPosition, ExtensionByteBit4Position)
		t_round_trip_loss_bit_flows_measurements_direction2 := analyzeOneDirectionalPcap_T_Round_Trip_Loss_Bit(s2_eth2_pcapFile, ip_2, SpinBitPosition, ExtensionByteBit4Position)

		if outputFile, err := os.Create(outputFileBaseName + "tbit.csv"); err == nil {

			for flow_id, measurements := range t_round_trip_loss_bit_flows_measurements_direction1 {
				for _, measurement := range measurements {
					outputFile.WriteString(fmt.Sprintf("%-s,%-s,%-s,%-s,%-s\n", flow_id, measurement.startTime.String(), measurement.endTime.String(), "Generation: "+strconv.Itoa(measurement.phase_counts[PhaseGeneration]), "Reflection: "+strconv.Itoa(measurement.phase_counts[PhaseReflection])))

				}
			}

			for flow_id, measurements := range t_round_trip_loss_bit_flows_measurements_direction2 {

				for _, measurement := range measurements {

					outputFile.WriteString(fmt.Sprintf("%-s,%-s,%-s,%-s,%-s\n", flow_id, measurement.startTime.String(), measurement.endTime.String(), "Generation: "+strconv.Itoa(measurement.phase_counts[PhaseGeneration]), "Reflection: "+strconv.Itoa(measurement.phase_counts[PhaseReflection])))
				}
			}

		} else {
			fmt.Println(err)
		}

	} else {
		fmt.Println("Skip T Round Trip Loss Bit Analysis")
	}

	if measurement_techniques == 42 || measurement_techniques == 43 {
		fmt.Println("Perform Q Square Bit Analysis")
		q_square_bit_flows_measurements_direction1 := analyzeOneDirectionalPcap_Q_Square_Bit(s2_eth1_pcapFile, ip_1, ExtensionByteBit1Position)
		q_square_bit_flows_measurements_direction2 := analyzeOneDirectionalPcap_Q_Square_Bit(s2_eth2_pcapFile, ip_2, ExtensionByteBit1Position)

		if outputFile, err := os.Create(outputFileBaseName + "qbit.csv"); err == nil {

			for flow_id, measurements := range q_square_bit_flows_measurements_direction1 {

				for _, measurement := range measurements {

					outputFile.WriteString(fmt.Sprintf("%-s,%-s,%-s,%-s,%-s,%-s,%-s\n", flow_id, measurement.startTime.String(), measurement.endTime.String(), "Phase: "+strconv.Itoa(measurement.phase_value), "Count: "+strconv.Itoa(measurement.phase_count), "Nominal Length:"+strconv.Itoa(measurement.nominal_period_length), "X Value:"+strconv.Itoa(measurement.nominal_x_value)))

				}
			}

			for flow_id, measurements := range q_square_bit_flows_measurements_direction2 {

				for _, measurement := range measurements {

					outputFile.WriteString(fmt.Sprintf("%-s,%-s,%-s,%-s,%-s,%-s,%-s\n", flow_id, measurement.startTime.String(), measurement.endTime.String(), "Phase: "+strconv.Itoa(measurement.phase_value), "Count: "+strconv.Itoa(measurement.phase_count), "Nominal Length:"+strconv.Itoa(measurement.nominal_period_length), "X Value:"+strconv.Itoa(measurement.nominal_x_value)))
				}
			}

		} else {
			fmt.Println(err)
		}

	} else {
		fmt.Println("Skip Q Square Bit Analysis")
	}

	if measurement_techniques == 42 || measurement_techniques == 43 {
		fmt.Println("Perform R Reflection Square Bit Analysis")
		r_reflection_square_bit_flows_measurements_direction1 := analyzeOneDirectionalPcap_R_Reflection_Square_Bit(s2_eth1_pcapFile, ip_1, ExtensionByteBit2Position, ExtensionByteBit1Position)
		r_reflection_square_bit_flows_measurements_direction2 := analyzeOneDirectionalPcap_R_Reflection_Square_Bit(s2_eth2_pcapFile, ip_2, ExtensionByteBit2Position, ExtensionByteBit1Position)

		if outputFile, err := os.Create(outputFileBaseName + "rbit.csv"); err == nil {

			for flow_id, measurements := range r_reflection_square_bit_flows_measurements_direction1 {

				for _, measurement := range measurements {

					outputFile.WriteString(fmt.Sprintf("%-s,%-s,%-s,%-s,%-s,%-s,%-s\n", flow_id, measurement.startTime.String(), measurement.endTime.String(), "Phase: "+strconv.Itoa(measurement.phase_value), "Count: "+strconv.Itoa(measurement.phase_count), "Nominal Length:"+strconv.Itoa(measurement.nominal_period_length), "X Value:"+strconv.Itoa(measurement.nominal_x_value)))

				}
			}

			for flow_id, measurements := range r_reflection_square_bit_flows_measurements_direction2 {

				for _, measurement := range measurements {

					outputFile.WriteString(fmt.Sprintf("%-s,%-s,%-s,%-s,%-s,%-s,%-s\n", flow_id, measurement.startTime.String(), measurement.endTime.String(), "Phase: "+strconv.Itoa(measurement.phase_value), "Count: "+strconv.Itoa(measurement.phase_count), "Nominal Length:"+strconv.Itoa(measurement.nominal_period_length), "X Value:"+strconv.Itoa(measurement.nominal_x_value)))
				}
			}

		} else {
			fmt.Println(err)
		}

	} else {
		fmt.Println("Skip R Reflection Square Bit Analysis")
	}
}

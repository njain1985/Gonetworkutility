//
// Query sniffer for MySQL or PostgreSQL.
// Print queries to stdout from either a pcap file or directly from a network interface.
//
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"gopkg.in/alecthomas/kingpin.v2"
	"log"
	"os"
	//"reflect"
	"strconv"
	"strings"
	"time"
)

// Autodetermine a resonable interface to listen on
// Use loop back if no other device has an IP
func getDevice() (iface string) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}
	for _, device := range devices {
		for _, address := range device.Addresses {
			// Set interface based on IPv4 address
			if len(strings.Split(string(address.IP.String()), ".")) == 4 {
				if iface == "" || iface == "lo" {
					iface = device.Name
				}
			}
		}
	}
	return iface
}

//
func main() {

	// Parameters used whether reading from a pcap file or a network interface
	var handle *pcap.Handle
	var err error

	// kingpin options and arguments
	var (
		file       = kingpin.Arg("file", "A filename or path to a pcap file.").String()
		plimit     = kingpin.Flag("count", "Exit after reading <count> packets. Defaults to 0.").Short('c').Default("0").Int()
		iface      = kingpin.Flag("iface", "The interface to listen on. Defaults to device with an IP.").Short('i').String()
		port       = kingpin.Flag("port", "A port to filter traffic on. Defaults to MySQL 3306 or Postgres 5432.").Short('p').Default("0").Int()
		packetType = kingpin.Flag("type", "The protocol type to dissect. Defaults to 'mysql'.").Short('t').Default("mysql").String()
		verbose    = kingpin.Flag("verbose", "Show verbose output.").Short('v').Bool()
	)

	// flag parser
	kingpin.CommandLine.HelpFlag.Short('h')
	//	kingpin.UsageTemplate(CustomUsageTemplate)
	kingpin.Parse()

	// Pivot method and setup env accordingly based on presence of command line argument
	if *file != "" {
		pcapFile := *file
		fmt.Fprintf(os.Stderr, "Reading from file %s\n", pcapFile)
		handle, err = pcap.OpenOffline(pcapFile)
	} else {
		// Specific settings used when doing a live capture off network device
		var (
			device       string        = getDevice()
			snapshot_len int32         = 65536
			promiscuous  bool          = true
			timeout      time.Duration = 30 * time.Second
		)
		if *iface != "" {
			device = *iface
		}
		fmt.Fprintf(os.Stderr, "Reading from interface %s\n", device)
		handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	}
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	p := 0 // Track each frame/packet
	badPackets := 0
	flows := map[string]string{} // Track users in flows.
	for packet := range packetSource.Packets() {
		applicationLayer := packet.ApplicationLayer()
		tstamp := packet.Metadata().CaptureInfo.Timestamp.UTC()
		packetLength := packet.Metadata().CaptureInfo.CaptureLength
		p++
		if applicationLayer != nil {
			tcpLayer := packet.Layer(layers.LayerTypeTCP)
			if tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)
				data := applicationLayer.Payload()
				payloadLength := len(data)
				bytesSeen := 0
				if *port > 0 {
					if int(tcp.DstPort) != *port {
						continue
					}
				}
				if *plimit > 0 && p > *plimit {
					fmt.Printf("Reached packet limit %d, exiting.\n", *plimit)
					os.Exit(1)
				}
				if int(tcp.DstPort) == *port && *packetType == "mysql" || tcp.DstPort == 3306 {
					netflow := packet.NetworkLayer().NetworkFlow()
					tcpflow := tcp.TransportFlow()
					flow := fmt.Sprintf("%s:%s", netflow.Src(), tcpflow.Src())
					//log.Println(netflow, tcpflow)
					// MySQL Wire Protocol: https://dev.mysql.com/doc/internals/en/mysql-packet.html
					// First 4 bytes make up the packet header which contains:
					//  - initial 3 bytes are the length of the payload beyond the 4 bytes for the header
					//  - 4th byte is the sequence ID
					// https://github.com/go-sql-driver/mysql/blob/e52f1902cae0a08f56b280b48b7cee3e403a33e2/packets.go
					if payloadLength >= 4 && len(data[bytesSeen+4:]) > 0 {
						// MySQL binary protocol uses least significant byte first.
						// https://dev.mysql.com/doc/internals/en/integer.html
						// Header of app layer.
						msgLength := int(uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16)
						bytesSeen += 3                  // 3 bytes for the palyoad length.
						msgId := uint8(data[bytesSeen]) // Sequence id for the exchange.
						bytesSeen += 1                  // The byte for seq/message id.
						// First byte of message payload is the command type.
						cmdType := int(data[bytesSeen])
						user := flows[flow]
						fmt.Printf("# Packet %d payloadBytes=%d msgLength=%d msgId=%d cmdType=%d\n", p, payloadLength, msgLength, msgId, cmdType)
						fmt.Printf("# %s %s:%s -> %s@%s:%s\n", tstamp, netflow.Src(), tcpflow.Src(), user, netflow.Dst(), tcpflow.Dst())
						fmt.Printf("# User: %s\n", user)
						switch cmdType {
						//case 1: // COM_QUIT
						case 3: // COM_QUERY
							bytesSeen += 1 // Command type
							fmt.Printf("%s;\n", data[bytesSeen:])
						//case 14: // COM_PING
						//						default:
						//							fmt.Printf("%d\n", cmdType)
						case 143: // Login Auth Request.
							//capabilities := binary.LittleEndian.Uint32(data[bytesSeen : bytesSeen+4])
							bytesSeen += 4  // 4 bytes for capabilities.
							bytesSeen += 4  // 4 bytes for max packet size.
							bytesSeen += 1  // 1 byte for charset.
							bytesSeen += 23 // 23 bytes of filler 0x00.
							user := string(data[bytesSeen : bytesSeen+bytes.IndexByte(data[bytesSeen:], 0)])
							userBytes := len(user) + 1
							bytesSeen += userBytes
							fmt.Printf("Login username: %s %s\n", user, flow)
							flows[flow] = string(user)
							//fmt.Printf("%s\n", pass)

							//byteLen = int(data[bytesSeen]) // Optional Scheama.
							//schema := data[bytesSeen:]
							//fmt.Printf("%s %d\n", schema, byteLen)
							//	default:
						}
						bytesSeen += 4 + msgLength
					}
				} else if *packetType == "postgres" && (int(tcp.DstPort) == *port || tcp.DstPort == 5432) {
					// Postgres wire protocol: https://www.postgresql.org/docs/9.5/static/protocol-overview.html
					//   - The first byte identifies the message type. (i.e. Q == simple query, P == prepared statement, etc...)
					//   - Next 4 bytes contain the length of the message with self included, but excluding the first byte for the msg type.
					//   - The remaining contents of the message are variable and determined by the message type.
					//   - For historical reasons, the very first message sent by the client (the startup message) has no initial message-type byte.
					if payloadLength > 5 {
						bytesLeft := payloadLength
						query := ""
						namedStatement := false
						// Since each packet's Postgres application payload can include multiple messages of varying types, with the leading
						// 5 bytes guiding to the end, continue interpreting bytes for each message until the full slice has been walked.
						for bytesSeen < payloadLength && len(data[bytesSeen:]) > 5 {
							// The 1st byte identifies the message type.
							msgType := string(data[bytesSeen])
							bytesSeen += 1
							// Decode the next 4 byte slice containing the message size as a 32 bit unsigned integer
							msgLength := binary.BigEndian.Uint32(data[bytesSeen : bytesSeen+4])
							bytesSeen += 4
							if payloadLength < (bytesSeen + int(msgLength) - 4) {
								badPackets++
								break
							}
							// Specific message formats: https://www.postgresql.org/docs/9.5/static/protocol-message-formats.html
							switch msgType {
							case "Q": // simple query
								fmt.Printf("# Packet %d packetBytes=%d payloadBytes=%d\n", p, packetLength, payloadLength)
								fmt.Printf("# %s\n", tstamp)
								q := strings.TrimSpace(string(data[bytesSeen:]))
								q = strings.Replace(q, "\t", "", -1)
								q = strings.Replace(q, "\n", "", -1)
								query = string(q)
								fmt.Printf("%s;\n", q)
							case "P": // parse command
								// Split byte slices on null terminated strings \0 (C-style strings)
								// https://www.postgresql.org/docs/9.5/static/protocol-message-types.html
								stmnt := data[bytesSeen:]
								statementName := string(bytes.Split(stmnt, []byte{0})[0])
								statement := string(bytes.Split(stmnt, []byte{0})[1])
								stlen := len(statementName) + len(statement) + 2 // bytes lost on split
								f := bytesSeen + stlen
								nTypes := binary.BigEndian.Uint16(data[f : f+2])
								f += 2
								if statementName == "" {
									statementName = "unnamed" + strconv.Itoa(p)
								}
								statement = strings.Replace(statement, "\n", "", -1)
								query = string(statement)
								if strings.Contains(query, "$") && nTypes > 0 {
									namedStatement = true
									fmt.Printf("# Packet %d packetBytes=%d payloadBytes=%d\n", p, packetLength, payloadLength)
									fmt.Printf("# %s\n", tstamp)
									fmt.Printf("PREPARE %s ", string(statementName))
								}
								if int(nTypes) > 0 {
									fmt.Printf("(")
									for i := 0; i < int(nTypes); i++ {
										oid := binary.BigEndian.Uint32(data[f : f+4])
										f += 4
										pType := "varchar"
										switch oid {
										case 0:
											pType = "varchar"
										case 16:
											pType = "bool"
										case 20:
											pType = "bigint"
										case 21:
											pType = "smallint"
										case 23:
											pType = "int"
										case 1043:
											pType = "varchar"
										}
										fmt.Printf("%s", pType)
										if i+1 != int(nTypes) {
											fmt.Printf(", ")
										}
									}
									fmt.Printf(") AS ")
								}
								if strings.Contains(query, "$") && nTypes > 0 {
									fmt.Printf("%s; ", statement)
								}
							case "B": // bind parameters
								stmnt := data[bytesSeen : bytesSeen+int(msgLength)-4]
								dstPortal := bytes.Split(stmnt, []byte{0})[0]
								statementName := string(bytes.Split(stmnt, []byte{0})[1])
								stlen := len(statementName) + len(dstPortal) + 2 // bytes lost on split
								f := bytesSeen + stlen
								nFP := binary.BigEndian.Uint16(data[f : f+2])
								f += 2
								formats := make([]int, nFP)
								for c := 0; c < int(nFP); c++ {
									formats[c] = int(binary.BigEndian.Uint16(data[f : f+2]))
									f += 2
								}
								nValues := binary.BigEndian.Uint16(data[f : f+2])
								f += 2
								if namedStatement && strings.Contains(query, "$") {
									statementName = "unnamed" + strconv.Itoa(p)
									fmt.Printf("EXECUTE %s(", statementName)
								}
								parameters := make([]string, nValues)
								if int(nValues) > 0 {
									for n := 0; n < int(nValues); n++ {
										format := 0
										if len(formats) > 0 {
											format = formats[n] // format text or binary
										}
										// # of bytes used by the parameter, excludes self
										vlen := binary.BigEndian.Uint32(data[f : f+4])
										f += 4
										// if vlen != 4294967295 && int(vlen) < len(data[f:]) {
										if vlen != 4294967295 {
											end := f + int(vlen)
											// skipping if byte length is longer than remaining bytes
											if int(vlen) > len(data[f:]) {
												fmt.Println()
												//fmt.Fprintf(os.Stderr, "ERROR: %d\n", format)
												break
											}
											param := data[f:end]
											pm := string(param)
											f += int(vlen)
											if format == 0 && namedStatement {
												parameters[n] = string(param)
												fmt.Printf("'%s'", string(param))
											} else { // binary type
												if namedStatement {
													switch int(vlen) {
													case 8:
														pm = strconv.Itoa(int(binary.BigEndian.Uint64(param)))
														fmt.Printf("%d", binary.BigEndian.Uint64(param))
													case 4:
														pm = strconv.Itoa(int(binary.BigEndian.Uint32(param)))
														fmt.Printf("%d", binary.BigEndian.Uint32(param))
													case 2:
														pm = strconv.Itoa(int(binary.BigEndian.Uint16(param)))
														fmt.Printf("%d", binary.BigEndian.Uint16(param))
													default:
														fmt.Printf("%s", param)
													}
												}
												parameters[n] = pm
											}
											if n+1 != int(nValues) && namedStatement {
												fmt.Printf(", ")
											}
										}
									}
								}

								if query != "" && int(nValues) == 0 && namedStatement {
									fmt.Printf("''")
								}
								if query != "" && namedStatement {
									fmt.Printf(");\n")
								}
								if !namedStatement && query != "" {
									fmt.Printf("# Packet %d packetBytes=%d payloadBytes=%d\n", p, packetLength, payloadLength)
									fmt.Printf("# %s\n", tstamp)
									for j := 0; j < len(parameters); j++ {
										k := j + 1
										varname := "$" + strconv.Itoa(k)
										param := parameters[j]
										param = strings.Replace(param, "'", "''", -1)
										query = strings.Replace(query, varname, "'"+param+"'", 1)
										if *verbose {
											fmt.Printf("# parameter %s %s\n", varname, param)
										}
									}
									fmt.Printf("%s;\n", query)
								}
								if *verbose {
									for i, pname := range parameters {
										format := 0
										if len(formats) > 0 {
											format = formats[i] // format text or binary
										}
										fmt.Printf("# DEBUG: format=%s param=%s\n", strconv.Itoa(format), pname)
									}
									fmt.Println()
								}
							}
							// Add message length excluding 4 bytes size header already tracked
							bytesSeen += int(msgLength) - 4
							bytesLeft = bytesLeft - bytesSeen
						}
					}
				}
			}
		}
	}
}

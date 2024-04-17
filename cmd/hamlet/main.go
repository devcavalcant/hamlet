package main

import (
	"log"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	dns     layers.DNS
	eth     layers.Ethernet
	ipv4    layers.IPv4
	ipv6    layers.IPv6
	tcp     layers.TCP
	udp     layers.UDP
	payload gopacket.Payload
	srcAddr string
	dstAddr string
)

func main() {

	args := os.Args[1:]
	var device = ""
	devices, err := pcap.FindAllDevs()

	if err != nil {
		log.Fatalln("Error during devices scanning", err)
	}

	for _, dev := range devices {
		if dev.Name == args[0] {
			device = dev.Name
		}
	}

	if device == "" {
		log.Fatalln("Couldn't find an interface with the name:", args[0])
	}

	live, err := pcap.OpenLive(device, 1600, true, pcap.BlockForever)

	if err != nil {
		log.Fatalln("Unable to start the sniffer due to error ", err)
	}

	defer live.Close()

	if err := live.SetBPFFilter("udp and port 53"); err != nil {
		log.Fatalln("Error during configuration of BPF Filters")
	}

	decodeParser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ipv4, &ipv6, &tcp, &udp, &dns, &payload)

	decodedLayers := make([]gopacket.LayerType, 0, 10)

	for {
		data, _, _ := live.ReadPacketData()

		decodeParser.DecodeLayers(data, &decodedLayers)

		for _, typo := range decodedLayers {

			if typo == layers.LayerTypeDNS {
				for _, question := range dns.Questions {
					println("[QUESTION] " + srcAddr + " --> " + dstAddr + " " + string(question.Name))
				}

				for _, answer := range dns.Answers {
					println("[ANSWER] " + srcAddr + " --> " + dstAddr + " " + answer.IP.String())
				}
			} else if typo == layers.LayerTypeIPv4 {
				srcAddr = ipv4.SrcIP.String()
				dstAddr = ipv4.DstIP.String()
			} else if typo == layers.LayerTypeIPv6 {
				srcAddr = ipv6.SrcIP.String()
				dstAddr = ipv6.DstIP.String()
			}

		}
	}
}

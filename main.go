package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
)

func init() {
	// set default log level
	log.SetLevel(log.InfoLevel)
	// register dnsCounter metric
	prometheus.MustRegister(dnsCounter)
}

func main() {
	var (
		iface        string
		promisc      bool
		snaplen      int
		verbose      bool
		httpHostPort string
	)

	// cli flags
	flag.StringVar(&iface, "interface", "", "interface to listen on")
	flag.BoolVar(&promisc, "promisc", true, "promiscuous mode")
	flag.BoolVar(&verbose, "verbose", false, "enable debug logging")
	flag.IntVar(&snaplen, "snaplen", 65536, "packet snap length")
	flag.StringVar(&httpHostPort, "httpHostPort", "localhost:9111", "<host>:<port> for exposing the metrics")
	flag.Parse()

	if verbose {
		log.SetLevel(log.DebugLevel)
	}

	if len(flag.Args()) == 0 {
		log.WithFields(log.Fields{
			"promiscuous": promisc,
			"snaplen":     snaplen,
		}).Info("No flags specified, using defaults")
	}

	// Start http server
	go func() {
		n, err := net.Listen("tcp", httpHostPort)
		if err != nil {
			log.Printf("error: failed to open prometheus listen port: %v\n", err)
			os.Exit(1)
		}
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.Handler())
		http.Serve(n, mux)
	}()

	switch strings.ToLower(iface) {
	case "", "any", "all":
		// find network interfaces
		devices, err := pcap.FindAllDevs()
		if err != nil {
			log.Fatal(err)
		}

		// get the first device with an IP address
		for _, device := range devices {
			if len(device.Addresses) > 0 {
				handle, err := pcap.OpenLive(device.Name, int32(snaplen), promisc, pcap.BlockForever)
				if err != nil {
					log.Fatal(err)
				}
				defer handle.Close()
				log.Infof("Listening on device: %s", device.Name)
				go listenToInterface(handle)
			}
		}
	default:
		handle, err := pcap.OpenLive(iface, int32(snaplen), promisc, pcap.BlockForever)
		if err != nil {
			log.Fatal(err)
		}
		defer handle.Close()
		log.Infof("Listening on device: %s", iface)
		listenToInterface(handle)
	}
}

func listenToInterface(handle *pcap.Handle) {
	// packet vars
	var (
		eth layers.Ethernet
		ip4 layers.IPv4
		ip6 layers.IPv6
		dst string
		src string
		tcp layers.TCP
		udp layers.UDP
		dns layers.DNS
	)

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &tcp, &udp, &dns)
	decodedLayers := []gopacket.LayerType{}

	packets := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packets.Packets() {
		parser.DecodeLayers(packet.Data(), &decodedLayers)
		// start dns logger
		dnsLog := log.WithFields(log.Fields{})

		// iterate through decoded packets
		for _, layerType := range decodedLayers {
			switch layerType {
			case layers.LayerTypeIPv4:
				src = ip4.SrcIP.String()
				dst = ip4.DstIP.String()
				dnsLog = dnsLog.WithFields(log.Fields{"src": src, "dst": dst})
			case layers.LayerTypeIPv6:
				src = ip6.DstIP.String()
				dst = ip6.DstIP.String()
				dnsLog = dnsLog.WithFields(log.Fields{"src": src, "dst": dst})
			case layers.LayerTypeDNS:
				dnsLog = dnsLog.WithFields(log.Fields{
					"opcode": dns.OpCode.String(),
					"rcode":  dns.ResponseCode.String(),
					"id":     uint16(dns.ID),
				})
				for _, query := range dns.Questions {
					fmt.Printf(" *** %v\n", string(query.Name))
					// type, class, opcode, rcode
					dnsCounter.WithLabelValues(string(query.Name), query.Type.String(), query.Class.String(), dns.OpCode.String(), dns.ResponseCode.String()).Inc()
					dnsLog.WithFields(log.Fields{
						"class": query.Class.String(),
						"name":  string(query.Name),
						"type":  query.Type.String(),
					}).Info("QUERY")
				}

			}
		}
	}
}

var (
	dnsCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "dns",
			Subsystem: "record",
			Name:      "counter",
			Help:      "DNS Record Total",
		},
		[]string{"name", "type", "class", "opcode", "rcode"},
	)
)

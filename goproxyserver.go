// goproxyserver
package main

import (
	//"flag"
	//"container/list"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/astaxie/beego/config"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	device       string = "em1"
	snapshot_len int32  = 1024
	promiscuous  bool   = false
	err          error
	timeout      time.Duration = 30 * time.Second
	handle       *pcap.Handle
	ethLayer     layers.Ethernet
	ipLayer      layers.IPv4
	tcpLayer     layers.UDP
)

var pcapdata chan []byte
var serverlist []string

func DoProxyJob() {
	//localaddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:31517")
	//conn, _ := net.ListenUDP("udp", localaddr)
	for {
		data := <-pcapdata
		fmt.Printf("Data length=%d.\n", len(data))
		for _, val := range data {
			fmt.Printf("0x%02X ", val)
		}
		fmt.Printf("\n")

		for _, val := range serverlist {
			dstaddr, err := net.ResolveUDPAddr("udp", val)
			if err != nil {
				fmt.Printf("Resolve udp addr failed:%s\n", err.Error())
				break
			}

			conn, err := net.DialUDP("udp", nil, dstaddr)

			n, err := conn.Write([]byte(data))
			if err != nil {
				fmt.Printf("Send data to %s failed:%s\n", val, err.Error())
			} else {
				fmt.Printf("Send %d bytes data to %s success\n", n, val)
			}

		}

	}
}

func main() {
	if len(os.Args) > 1 {
		fmt.Printf("The proxy server golang version v1.0.\n")
		fmt.Printf("Any parameters to display this message.\n")
		fmt.Printf("Modify configures in config.ini.\n\n")
		return
	}
	iniconf, err := config.NewConfig("ini", "config.ini")
	if err != nil {
		log.Fatal(err)
	}

	device := iniconf.String("Main::interface")
	filterforpcap := iniconf.String("Main::filter")
	servers := iniconf.String("Main::servers")
	fmt.Println("Capturing on device:", device)
	fmt.Println("The filter is:", filterforpcap)

	serverlist = strings.Split(servers, ",")
	/*for i, val := range serverlist {
		fmt.Println(i, ":", val)
	}*/

	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()
	err = handle.SetBPFFilter(filterforpcap)
	if err != nil {
		log.Fatal(err)
	}

	pcapdata = make(chan []byte, 4096)
	go DoProxyJob()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		//fmt.Println(packet)
		parser := gopacket.NewDecodingLayerParser(
			layers.LayerTypeEthernet,
			&ethLayer,
			&ipLayer,
			&tcpLayer,
		)
		foundLayerTypes := []gopacket.LayerType{}

		err := parser.DecodeLayers(packet.Data(), &foundLayerTypes)
		if err != nil {
			fmt.Println("Trouble decoding layers: ", err)
		}

		for _, layerType := range foundLayerTypes {
			if layerType == layers.LayerTypeIPv4 {
				fmt.Println("IPv4: ", ipLayer.SrcIP, "->", ipLayer.DstIP)
			}
		}
		applicationLayer := packet.ApplicationLayer()
		if applicationLayer != nil {
			//fmt.Println("Application layer/Payload found.")
			//fmt.Printf("%s\n", applicationLayer.Payload())
			//ShowHexPacket(applicationLayer.Payload())

			pcapdata <- applicationLayer.Payload()
		}
	}
}

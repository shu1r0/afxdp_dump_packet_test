package main

import (
	"flag"
	"log"

	"github.com/google/gopacket"
	"github.com/shu1r0/tamperpacket/pkg/xdpsk"
)

func main() {
	var link string
	var qid int

	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)

	flag.StringVar(&link, "link", "enp0s3", "The network link on which rebroadcast should run on.")
	flag.IntVar(&qid, "queueid", 0, "The ID of the Rx queue to which to attach to on the network link.")
	flag.Parse()

	xsk, err := xdpsk.NewXDPSocket(qid, link)
	if err != nil {
		log.Fatalln("Socket Create Error %s", err)
	}

	xsk.OnPacket(func(pkt gopacket.Packet) {
		log.Printf("received frame:\n%+v", pkt)
	})
}

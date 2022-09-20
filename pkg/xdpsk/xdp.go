package xdpsk

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/asavie/xdp"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

type XDPSocket struct {
	Prog    *xdp.Program
	Sk      *xdp.Socket
	Qid     int
	IfaceId int
}

func NewXDPSocket(qid int, iface string) (*XDPSocket, error) {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return nil, err
	}
	xsk := &XDPSocket{Qid: qid, IfaceId: link.Attrs().Index}

	// XDP
	prog, err := NewTamperProgram(nil)
	xsk.Prog = prog
	if err != nil {
		return nil, err
	}

	if err := netlink.LinkSetXdpFdWithFlags(link, prog.Program.FD(), nl.XDP_FLAGS_SKB_MODE); err != nil {
		// if err := prog.Attach(link.Attrs().Index); err != nil {
		return nil, err
	}

	// Create AF_XDP Socket
	sk, err := xdp.NewSocket(link.Attrs().Index, qid, nil)
	xsk.Sk = sk
	if err != nil {
		return nil, err
	}

	if err := prog.Register(qid, sk.FD()); err != nil {
		return nil, err
	}

	return xsk, nil
}

func (xsk *XDPSocket) Close() {
	xsk.Prog.Close()
	xsk.Prog.Detach(xsk.IfaceId)
	xsk.Prog.Unregister(xsk.Qid)
}

type OnPacketFunc func(gopacket.Packet)

func (xsk *XDPSocket) OnPacket(cb OnPacketFunc) {
	for {
		fmt.Println("Polling ....")
		if n := xsk.Sk.NumFreeFillSlots(); n > 0 {
			xsk.Sk.Fill(xsk.Sk.GetDescs(n))
		}

		numRx, _, err := xsk.Sk.Poll(-1)
		if err != nil {
			fmt.Errorf("Socket Polling Error")
		}

		if numRx > 0 {
			rxD := xsk.Sk.Receive(numRx)

			for i := 0; i < len(rxD); i++ {
				pktRaw := xsk.Sk.GetFrame(rxD[i])
				pkt := gopacket.NewPacket(pktRaw, layers.LayerTypeEthernet, gopacket.Default)
				cb(pkt)
			}
		}
	}

}

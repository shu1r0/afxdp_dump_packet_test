package xdpsk

import (
	"github.com/asavie/xdp"
	"github.com/cilium/ebpf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go TamperPkt ../../bpf/tamper.c -- -I../../bpf/ -I/usr/include/ -nostdinc -O3

type Collect struct {
	Prog    *ebpf.Program `ebpf:"xdp_tamper"`
	XsksMap *ebpf.Map     `ebpf:"xsks_map"`
	QidMap  *ebpf.Map     `ebpf:"qid_map"`
}

func NewTamperProgram(options *ebpf.CollectionOptions) (*xdp.Program, error) {
	spec, err := LoadTamperPkt()
	if err != nil {
		return nil, err
	}

	co := &Collect{}
	if err := spec.LoadAndAssign(co, options); err != nil {
		return nil, err
	}

	pro := &xdp.Program{Program: co.Prog, Queues: co.QidMap, Sockets: co.XsksMap}
	return pro, nil
}

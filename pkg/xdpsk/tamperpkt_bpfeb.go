// Code generated by bpf2go; DO NOT EDIT.
//go:build arm64be || armbe || mips || mips64 || mips64p32 || ppc64 || s390 || s390x || sparc || sparc64
// +build arm64be armbe mips mips64 mips64p32 ppc64 s390 s390x sparc sparc64

package xdpsk

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// LoadTamperPkt returns the embedded CollectionSpec for TamperPkt.
func LoadTamperPkt() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_TamperPktBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load TamperPkt: %w", err)
	}

	return spec, err
}

// LoadTamperPktObjects loads TamperPkt and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//     *TamperPktObjects
//     *TamperPktPrograms
//     *TamperPktMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func LoadTamperPktObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := LoadTamperPkt()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// TamperPktSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type TamperPktSpecs struct {
	TamperPktProgramSpecs
	TamperPktMapSpecs
}

// TamperPktSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type TamperPktProgramSpecs struct {
	XdpTamper *ebpf.ProgramSpec `ebpf:"xdp_tamper"`
}

// TamperPktMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type TamperPktMapSpecs struct {
	QidMap  *ebpf.MapSpec `ebpf:"qid_map"`
	XsksMap *ebpf.MapSpec `ebpf:"xsks_map"`
}

// TamperPktObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to LoadTamperPktObjects or ebpf.CollectionSpec.LoadAndAssign.
type TamperPktObjects struct {
	TamperPktPrograms
	TamperPktMaps
}

func (o *TamperPktObjects) Close() error {
	return _TamperPktClose(
		&o.TamperPktPrograms,
		&o.TamperPktMaps,
	)
}

// TamperPktMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to LoadTamperPktObjects or ebpf.CollectionSpec.LoadAndAssign.
type TamperPktMaps struct {
	QidMap  *ebpf.Map `ebpf:"qid_map"`
	XsksMap *ebpf.Map `ebpf:"xsks_map"`
}

func (m *TamperPktMaps) Close() error {
	return _TamperPktClose(
		m.QidMap,
		m.XsksMap,
	)
}

// TamperPktPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to LoadTamperPktObjects or ebpf.CollectionSpec.LoadAndAssign.
type TamperPktPrograms struct {
	XdpTamper *ebpf.Program `ebpf:"xdp_tamper"`
}

func (p *TamperPktPrograms) Close() error {
	return _TamperPktClose(
		p.XdpTamper,
	)
}

func _TamperPktClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//go:embed tamperpkt_bpfeb.o
var _TamperPktBytes []byte

package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type EAPinfo struct {
	EAPtypes   []int
	Identities []string
}

func ParseEAP(packet gopacket.Packet) (ok bool, i EAPinfo) {
	ok = false
	for _, layer := range packet.Layers() {
		if layer.LayerType() == layers.LayerTypeEAP {
			if data, infoOk := layer.(*layers.EAP); infoOk {
				i.EAPtypes = append(i.EAPtypes, int(data.Type))
				ok = true
			}
		}
	}
	return ok, i
}

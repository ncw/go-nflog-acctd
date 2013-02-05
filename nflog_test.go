package main

import (
	"testing"
)

func BenchmarkProcessPacketSameAddress(b *testing.B) {
	// FIXME set period
	//*Debug = true
	b.StopTimer()
	a := NewAccounting()
	a.Start()

	nflog := &NfLog{
		IpVersion: 4,
		Direction: IpSource,
		IpPacket:  Ip4Packet,
		a:         a,
	}
	var seq uint32 = 0
	b.StartTimer()
	packet := make([]byte, 20)
	packet[IpVersion] = 4 << IpVersionShift
	// FIXME set size etc
	for i := 0; i < b.N; {
		ps := <-nflog.a.returnAddPackets
		nflog.addPackets = ps[:0]
		// Process a chunk of 100 packets
		for j := 0; j < 100; j++ {
			nflog.ProcessPacket(packet, seq)
			seq++
			i++
		}
		nflog.a.processAddPackets <- nflog.addPackets
		nflog.addPackets = nil
	}
	// FIXME should wait until chan empty
	b.StopTimer()
	a.Stop()
	b.StartTimer()
}

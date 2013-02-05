package main

import (
	"io/ioutil"
	"log"
	"testing"
	"time"
)

var ip4packet = []byte{0x45, 0x0, 0x0, 0x97, 0x0, 0x0, 0x40, 0x0, 0x40, 0x11, 0x26, 0x23, 0xa, 0x15, 0x0, 0x1, 0xa, 0x15, 0x0, 0x9}

var ip6packet = []byte{0x60, 0x0, 0x0, 0x0, 0x0, 0x40, 0x3a, 0x40, 0x20, 0x1, 0x4, 0x70, 0x1f, 0x8, 0x2, 0xde, 0xf0, 0xf, 0x39, 0xaa, 0x2, 0xb2, 0x94, 0xc, 0x2a, 0x0, 0x14, 0x50, 0x40, 0xc, 0xc, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x69}

func StartAccounting(b *testing.B) *Accounting {
	// FIXME set period
	//*Debug = true
	b.StopTimer()
	log.SetOutput(ioutil.Discard)
	a := NewAccounting()
	a.Start()
	b.StartTimer()
	return a
}

func StopAccounting(b *testing.B, a *Accounting) {
	// Wait until the channel is empty and has been processed
	for len(a.processAddPackets) > 0 && len(a.returnAddPackets) != AddPacketsQueueSize {
		time.Sleep(time.Microsecond)
	}

	// FIXME should wait until chan empty
	b.StopTimer()
	a.Stop()
	b.StartTimer()
}

func Benchmark_ProcessIPv4Packet_ConstantAddress(b *testing.B) {
	a := StartAccounting(b)
	nflog := &NfLog{
		IpVersion: 4,
		Direction: IpSource,
		IpPacket:  Ip4Packet,
		a:         a,
	}
	var seq uint32 = 0
	for i := 0; i < b.N; {
		ps := <-nflog.a.returnAddPackets
		nflog.addPackets = ps[:0]
		// Process a chunk of 100 packets
		for j := 0; j < 100; j++ {
			nflog.ProcessPacket(ip4packet, seq)
			seq++
			i++
		}
		nflog.a.processAddPackets <- nflog.addPackets
		nflog.addPackets = nil
	}
	StopAccounting(b, a)
}

func Benchmark_ProcessIPv4Packet_256Addresses(b *testing.B) {
	a := StartAccounting(b)
	nflog := &NfLog{
		IpVersion: 4,
		Direction: IpSource,
		IpPacket:  Ip4Packet,
		a:         a,
	}
	var seq uint32 = 0
	iAddr := Ip4Packet.SrcOffset + 3
	for i := 0; i < b.N; {
		ps := <-nflog.a.returnAddPackets
		nflog.addPackets = ps[:0]
		// Process a chunk of 100 packets
		for j := 0; j < 100; j++ {
			ip4packet[iAddr] = byte(seq)
			nflog.ProcessPacket(ip4packet, seq)
			seq++
			i++
		}
		nflog.a.processAddPackets <- nflog.addPackets
		nflog.addPackets = nil
	}
	StopAccounting(b, a)
}

func Benchmark_ProcessIPv4Packet_65536Addresses(b *testing.B) {
	a := StartAccounting(b)
	nflog := &NfLog{
		IpVersion: 4,
		Direction: IpSource,
		IpPacket:  Ip4Packet,
		a:         a,
	}
	var seq uint32 = 0
	iAddr1 := Ip4Packet.SrcOffset + 2
	iAddr2 := Ip4Packet.SrcOffset + 3
	for i := 0; i < b.N; {
		ps := <-nflog.a.returnAddPackets
		nflog.addPackets = ps[:0]
		// Process a chunk of 100 packets
		for j := 0; j < 100; j++ {
			ip4packet[iAddr1] = byte(seq)
			ip4packet[iAddr2] = byte(seq >> 8)
			nflog.ProcessPacket(ip4packet, seq)
			seq++
			i++
		}
		nflog.a.processAddPackets <- nflog.addPackets
		nflog.addPackets = nil
	}
	StopAccounting(b, a)
}

func Benchmark_ProcessIPv6Packet_ConstantAddress(b *testing.B) {
	a := StartAccounting(b)
	nflog := &NfLog{
		IpVersion: 6,
		Direction: IpSource,
		IpPacket:  Ip6Packet,
		a:         a,
	}
	var seq uint32 = 0
	for i := 0; i < b.N; {
		ps := <-nflog.a.returnAddPackets
		nflog.addPackets = ps[:0]
		// Process a chunk of 100 packets
		for j := 0; j < 100; j++ {
			nflog.ProcessPacket(ip6packet, seq)
			seq++
			i++
		}
		nflog.a.processAddPackets <- nflog.addPackets
		nflog.addPackets = nil
	}
	StopAccounting(b, a)
}

// Parse and account IP packets

package main

import (
	"fmt"
	"net"
)

const (
	// How to read the IP version number from an IP packet
	IpVersion      = 0
	IpVersionShift = 4
	IpVersionMask  = 0x0f
)

// Describe the header of an IPv4 or IPv6 packet
type IpPacketInfo struct {
	LengthOffset int
	SrcOffset    int
	DstOffset    int
	HeaderSize   int
	AddrLen      int
}

// Read the source address from an IP packet
func (i *IpPacketInfo) Src(packet []byte) net.IP {
	return net.IP(packet[i.SrcOffset : i.SrcOffset+i.AddrLen])
}

// Read the destination address from an IP packet
func (i *IpPacketInfo) Dst(packet []byte) net.IP {
	return net.IP(packet[i.DstOffset : i.DstOffset+i.AddrLen])
}

// Read the length from an IP packet
func (i *IpPacketInfo) Length(packet []byte) int {
	return int(packet[i.LengthOffset])<<8 + int(packet[i.LengthOffset+1])
}

var Ip4Packet = &IpPacketInfo{
	// 20 bytes IPv4 Header - http://en.wikipedia.org/wiki/IPv4
	LengthOffset: 2,
	SrcOffset:    12,
	DstOffset:    16,
	HeaderSize:   20,
	AddrLen:      4,
}

var Ip6Packet = &IpPacketInfo{
	// 40 bytes IPv6 Header - http://en.wikipedia.org/wiki/IPv6_packet
	LengthOffset: 4,
	SrcOffset:    8,
	DstOffset:    24,
	HeaderSize:   40,
	AddrLen:      16,
}

// Account is packet which needs accounting
type Packet struct {
	// Direction: Source address (true) or destination address (false)
	Direction IpDirection
	// The address
	Addr net.IP
	// Length of the packet
	Length int
	// IP Version (4 or 6)
	IpVersion byte
}

// Convert a packet to printable
func (p *Packet) String() string {
	return fmt.Sprintf("IPv%d message %s Addr %s Size %d", p.IpVersion, p.Direction, p.Addr, p.Length)
}

// Check it implements the interface
var _ fmt.Stringer = &Packet{}

type IpDirection bool

func (sod IpDirection) String() string {
	if sod {
		return "Source"
	}
	return "Dest"
}

const (
	IpSource = IpDirection(true)
	IpDest   = IpDirection(false)
)

// Check it implements the interface
var _ fmt.Stringer = IpDirection(false)

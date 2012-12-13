// Use cgo to interface with nflog
//
// Debian packages for these header files: iptables-dev and linux-libc-dev

// FIXME why the whole packet arriving and not just the headers?
// FIXME what does copy packet do?

package main

import (
	"log"
	"syscall"
	"unsafe"
	"net"
)

/*
#cgo LDFLAGS: -lnetfilter_log
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <libnetfilter_log/libnetfilter_log.h>

// Forward definition of Go function
void goCallback(char *, int, void *);

// Callback to hand the data back to Go
static int _callback(struct nflog_g_handle *gh, struct nfgenmsg *nfmsg, struct nflog_data *nfd, void *data) {
	char *prefix = nflog_get_prefix(nfd);
	char *payload = 0;
	int payload_len = nflog_get_payload(nfd, &payload);
	// Could read timestamp nflog_get_timestamp(nfd, &tv)
	// Could read devices: nflog_get_indev(nfd) and nflog_get_outdev(nfd)
	goCallback(prefix, payload_len, payload);
	return 0;
 }

// Register the callback - can't be done from Go
static int _callback_register(struct nflog_g_handle *gh, void *data) {
	return nflog_callback_register(gh, _callback, data);
}
*/
import "C"

const (
	MAX_CAPLEN = 4096
	McastGroupIPv4 = 4
	McastGroupIPv6 = 6

	// How to read the IP version number from an IP packet
	IpVersion      = 0
	IpVersionShift = 4
	IpVersionMask  = 0x0f
)

// NfLog
type NfLog struct {
	// Main nflog_handle
	h *C.struct_nflog_handle
	// File descriptor for socket operations
	fd int
	// Group handles
	ghs []*C.struct_nflog_g_handle
}

// Current nflog error
func nflog_error() error {
	return syscall.Errno(C.nflog_errno)
}

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
	LengthOffset : 2,
	SrcOffset    : 12,
	DstOffset    : 16,
	HeaderSize   : 20,
	AddrLen      : 4,
}

var Ip6Packet = &IpPacketInfo{ 
	// 40 bytes IPv6 Header - http://en.wikipedia.org/wiki/IPv6_packet
	LengthOffset : 4,
	SrcOffset    : 8,
	DstOffset    : 24,
	HeaderSize   : 40,
	AddrLen      : 16,
}

//export goCallback
func goCallback(cprefix *C.char, payload_len C.int, payload unsafe.Pointer) {
	//prefix := C.GoString(cprefix)
	packet := C.GoBytes(payload, payload_len)
	// Peek the IP Version out of the header
	ip_version := packet[IpVersion] >> IpVersionShift & IpVersionMask
	// log.Printf("Received %s: size %d, IPv%d", prefix, payload_len, ip_version)
	var i *IpPacketInfo
	switch ip_version {
	case 4:
		i = Ip4Packet
	case 6:
		i = Ip6Packet
	default:
		log.Printf("Bad IP version: %d", ip_version)
		return
	}
	if len(packet) < i.HeaderSize {
		log.Printf("Short IPv%s packet %d/%d bytes", ip_version, len(packet), i.HeaderSize)
		return
	}
	src := i.Src(packet)
	dst := i.Dst(packet)
	length := i.Length(packet)
	log.Printf("IPv%d message From %s To %s Size %d", ip_version, src, dst, length)
}

// Connects to the group specified with the size
func (nflog *NfLog) makeGroup(group, size int) {
	log.Printf("Binding this socket to group %d", group)
	gh := C.nflog_bind_group(nflog.h, (C.u_int16_t)(group))
	if gh == nil {
		log.Fatal("nflog_bind_group failed: %s", nflog_error())
	}

	//C.nflog_callback_register(gh, nflog_callback, nil)
	C._callback_register(gh, nil)

	// FIXME set nflog_set_timeout?

	// FIXME do we need this? Should set large
	if C.nflog_set_qthresh(gh, 1024) < 0 {
		log.Fatal("nflog_set_qthresh failed: %s", nflog_error())
	}

	log.Printf("Setting copy_packet mode to %d bytes", size)
	if C.nflog_set_mode(gh, C.NFULNL_COPY_PACKET, (C.uint)(size)) < 0 {
		log.Fatal("nflog_set_mode failed: %s", nflog_error())
	}

	nflog.ghs = append(nflog.ghs, gh)
}

// Open the nflog
func NewNfLog() *NfLog {
	h := C.nflog_open()
	if h == nil {
		log.Fatal("Failed to open NFLOG: %s", nflog_error())
	}
	log.Println("Binding nfnetlink_log to AF_INET")
	if C.nflog_bind_pf(h, C.AF_INET) < 0 {
		log.Fatal("nflog_bind_pf failed: %s", nflog_error())
	}

	nflog := &NfLog{
		h: h,
		fd: int(C.nflog_fd(h)),
	}
	nflog.makeGroup(McastGroupIPv4, Ip4Packet.HeaderSize)
	nflog.makeGroup(McastGroupIPv6, Ip6Packet.HeaderSize)
	return nflog
}

// Receive packets in a loop forever
func (nflog *NfLog) Loop() {
	buf := make([]byte, syscall.Getpagesize())
	for {
		nr, _, e := syscall.Recvfrom(nflog.fd, buf, 0)
		if e != nil {
			log.Printf("Recvfrom failed: %s", e)
		}
		// Handle messages in packet
		C.nflog_handle_packet(nflog.h, (* C.char)(unsafe.Pointer(&buf[0])), (C.int)(nr));
	}

}

// Close the NfLog down
func (nflog *NfLog) Close() {
	log.Printf("Unbinding this socket from %d groups", len(nflog.ghs))
	for _, gh := range nflog.ghs {
		C.nflog_unbind_group(gh)
	}
	log.Printf("Closing NFLOG")
	C.nflog_close(nflog.h)
}

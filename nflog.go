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

	// Shared
	IpVersion      = 0
	IpVersionShift = 4
	IpVersionMask  = 0x0f

	// 20 bytes IPv4 Header - http://en.wikipedia.org/wiki/IPv4
	Ip4LengthOffest = 2
	Ip4SrcOffset    = 12
	Ip4DstOffset    = 16
	Ip4HeaderSize   = 20

	// 40 bytes IPv6 Header - http://en.wikipedia.org/wiki/IPv6_packet
	Ip6LengthOffest = 4
	Ip6SrcOffset    = 8
	Ip6DstOffset    = 24
	Ip6HeaderSize   = 40
)

// NfLog
type NfLog struct {
	h *C.struct_nflog_handle
	fd int
	qh4, qh6 *C.struct_nflog_g_handle
}

// Current nflog error
func nflog_error() error {
	return syscall.Errno(C.nflog_errno)
}

//export goCallback
func goCallback(cprefix *C.char, payload_len C.int, payload unsafe.Pointer) {
	prefix := C.GoString(cprefix)
	packet := C.GoBytes(payload, payload_len)
	// Peek the IP Version out of the header
	ip_version := packet[IpVersion] >> IpVersionShift & IpVersionMask
	log.Printf("Received %s: size %d, IPv%d", prefix, payload_len, ip_version)
	var src, dst net.IP
	var length int
	switch ip_version {
	case 4:
		if len(packet) < Ip4HeaderSize {
			log.Printf("Short IPv4 packet %d bytes", len(packet))
			return
		}
		src = net.IP(packet[Ip4SrcOffset : Ip4SrcOffset+4])
		dst = net.IP(packet[Ip4DstOffset : Ip4DstOffset+4])
		length = int(packet[Ip4LengthOffest])<<8 + int(packet[Ip4LengthOffest+1])
	case 6:
		if len(packet) < Ip6HeaderSize {
			log.Printf("Short IPv6 packet %d bytes", len(packet))
			return
		}
		src = net.IP(packet[Ip6SrcOffset : Ip6SrcOffset+16])
		dst = net.IP(packet[Ip6DstOffset : Ip6DstOffset+16])
		length = int(packet[Ip6LengthOffest])<<8 + int(packet[Ip6LengthOffest+1])
	default:
		log.Printf("Bad IP version: %d", ip_version)
		return
	}
	log.Printf("IPv%d message From %s To %s Size %d", ip_version, src, dst, length)
}

// Connects to the group specified with the size
func (nflog *NfLog) makeGroup(group, size uint) *C.struct_nflog_g_handle {
	log.Printf("Binding this socket to group %d", group)
	qh := C.nflog_bind_group(nflog.h, (C.u_int16_t)(group))
	if qh == nil {
		log.Fatal("nflog_bind_group failed: %s", nflog_error())
	}

	//C.nflog_callback_register(qh, nflog_callback, nil)
	C._callback_register(qh, nil)

	// FIXME set nflog_set_timeout?

	// FIXME do we need this? Should set large
	if C.nflog_set_qthresh(qh, 1024) < 0 {
		log.Fatal("nflog_set_qthresh failed: %s", nflog_error())
	}

	log.Printf("Setting copy_packet mode to %d bytes", size)
	if C.nflog_set_mode(qh, C.NFULNL_COPY_PACKET, (C.uint)(size)) < 0 {
		log.Fatal("nflog_set_mode failed: %s", nflog_error())
	}

	return qh
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
	nflog.qh4 = nflog.makeGroup(McastGroupIPv4, Ip4HeaderSize)
	nflog.qh6 = nflog.makeGroup(McastGroupIPv6, Ip6HeaderSize)
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
	log.Printf("Unbinding this socket from group %d", McastGroupIPv4)
	C.nflog_unbind_group(nflog.qh4)
	log.Printf("Unbinding this socket from group %d", McastGroupIPv6)
	C.nflog_unbind_group(nflog.qh6)
	log.Printf("Closing NFLOG")
	C.nflog_close(nflog.h)
}

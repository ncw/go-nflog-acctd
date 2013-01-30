// Use cgo to interface with nflog
//
// Debian packages needed:
//   apt-get install iptables-dev linux-libc-dev libnetfilter-log-dev

// FIXME why the whole packet arriving and not just the headers?
// FIXME what does copy packet do?

package main

import (
	"log"
	"net"
	"syscall"
	"unsafe"
)

/*
#cgo LDFLAGS: -lnetfilter_log
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <libnetfilter_log/libnetfilter_log.h>

// Forward definition of Go function
void goCallback(void *, char *, int, void *);

// Callback to hand the data back to Go
static int _callback(struct nflog_g_handle *gh, struct nfgenmsg *nfmsg, struct nflog_data *nfd, void *data) {
	char *prefix = nflog_get_prefix(nfd);
	char *payload = 0;
	int payload_len = nflog_get_payload(nfd, &payload);
	// Could read timestamp nflog_get_timestamp(nfd, &tv)
	// Could read devices: nflog_get_indev(nfd) and nflog_get_outdev(nfd)
	goCallback(data, prefix, payload_len, payload);
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
)

// NfLog
type NfLog struct {
	// Main nflog_handle
	h *C.struct_nflog_handle
	// File descriptor for socket operations
	fd int
	// Group handles
	ghs []*C.struct_nflog_g_handle
	// The multicast address
	McastGroup int
	// Flavour of IP we are expecting, 4 or 6
	IpVersion byte
	// Are we account the source or the destination address
	Direction IpDirection
	// Flavour of IP packet we are decoding
	IpPacket *IpPacketInfo
	// Accounting
	a *Accounting
	// Quit the loop
	quit bool
}

// Create a new NfLog
//
// McastGroup is that specified in ip[6]tables
// IPv6 is a flag to say if it is IPv6 or not
// Direction is to monitor the source address or the dest address
func NewNfLog(McastGroup int, IpVersion byte, Direction IpDirection, a *Accounting) *NfLog {
	h := C.nflog_open()
	if h == nil {
		log.Fatalf("Failed to open NFLOG: %s", nflog_error())
	}
	log.Println("Binding nfnetlink_log to AF_INET")
	if C.nflog_bind_pf(h, C.AF_INET) < 0 {
		log.Fatalf("nflog_bind_pf failed: %s", nflog_error())
	}

	nflog := &NfLog{
		h:          h,
		fd:         int(C.nflog_fd(h)),
		McastGroup: McastGroup,
		IpVersion:  IpVersion,
		Direction:  Direction,
		a:          a,
	}
	switch IpVersion {
	case 4:
		nflog.IpPacket = Ip4Packet
	case 6:
		nflog.IpPacket = Ip6Packet
	default:
		log.Fatalf("Bad IP version %d", IpVersion)
	}
	nflog.makeGroup(McastGroup, nflog.IpPacket.HeaderSize)
	return nflog
}

// Receive data from nflog on a callback from C
//
//export goCallback
func goCallback(_nflog unsafe.Pointer, cprefix *C.char, payload_len C.int, payload unsafe.Pointer) {
	nflog := (*NfLog)(_nflog)
	//prefix := C.GoString(cprefix)
	packet := C.GoBytes(payload, payload_len)
	// Peek the IP Version out of the header
	ip_version := packet[IpVersion] >> IpVersionShift & IpVersionMask
	// log.Printf("Received %s: size %d, IPv%d", prefix, payload_len, ip_version)
	if ip_version != nflog.IpVersion {
		log.Printf("Bad IP version: %d", ip_version)
		return
	}
	i := nflog.IpPacket
	if len(packet) < i.HeaderSize {
		log.Printf("Short IPv%s packet %d/%d bytes", ip_version, len(packet), i.HeaderSize)
		return
	}

	var addr net.IP
	if nflog.Direction {
		addr = i.Src(packet)
	} else {
		addr = i.Dst(packet)
	}
	nflog.a.Packet(nflog.Direction, addr, i.Length(packet), ip_version)
}

// Current nflog error
func nflog_error() error {
	return syscall.Errno(C.nflog_errno)
}

// Connects to the group specified with the size
func (nflog *NfLog) makeGroup(group, size int) {
	log.Printf("Binding this socket to group %d", group)
	gh := C.nflog_bind_group(nflog.h, (C.u_int16_t)(group))
	if gh == nil {
		log.Fatalf("nflog_bind_group failed: %s", nflog_error())
	}

	//C.nflog_callback_register(gh, nflog_callback, nil)
	C._callback_register(gh, unsafe.Pointer(nflog))

	// FIXME set nflog_set_timeout?

	// FIXME do we need this? Should set large
	if C.nflog_set_qthresh(gh, 1024) < 0 {
		log.Fatalf("nflog_set_qthresh failed: %s", nflog_error())
	}

	log.Printf("Setting copy_packet mode to %d bytes", size)
	if C.nflog_set_mode(gh, C.NFULNL_COPY_PACKET, (C.uint)(size)) < 0 {
		log.Fatalf("nflog_set_mode failed: %s", nflog_error())
	}

	nflog.ghs = append(nflog.ghs, gh)
}

// Receive packets in a loop until quit
func (nflog *NfLog) Loop() {
	buf := make([]byte, syscall.Getpagesize())
	for !nflog.quit {
		nr, _, e := syscall.Recvfrom(nflog.fd, buf, 0)
		if e != nil {
			log.Printf("Recvfrom failed: %s", e)
		}
		// Handle messages in packet
		C.nflog_handle_packet(nflog.h, (*C.char)(unsafe.Pointer(&buf[0])), (C.int)(nr))
	}

}

// Close the NfLog down
func (nflog *NfLog) Close() {
	log.Printf("Unbinding this socket from %d groups", len(nflog.ghs))
	nflog.quit = true
	for _, gh := range nflog.ghs {
		C.nflog_unbind_group(gh)
	}
	log.Printf("Closing NFLOG")
	C.nflog_close(nflog.h)
}

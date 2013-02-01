// Use cgo to interface with nflog
//
// Docs: http://www.netfilter.org/projects/libnetfilter_log/doxygen/index.html
//
// Debian packages needed:
//   apt-get install iptables-dev linux-libc-dev libnetfilter-log-dev

// FIXME Get this under heavy load - ENOBUFS
// 2013/01/31 17:38:21 Recvfrom failed: no buffer space available
// Seems to be caused by buffer overflow

package main

import (
	"log"
	"net"
	"reflect"
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
void goCallback(void *, u_int32_t, int, void *);

// Callback to hand the data back to Go
static int _callback(struct nflog_g_handle *gh, struct nfgenmsg *nfmsg, struct nflog_data *nfd, void *data) {
	char *payload = 0;
	int payload_len = nflog_get_payload(nfd, &payload);
	u_int32_t seq = 0;
	nflog_get_seq(nfd, &seq);
	goCallback(data, seq, payload_len, payload);
	return 0;
 }

// Register the callback - can't be done from Go
static int _callback_register(struct nflog_g_handle *gh, void *data) {
	return nflog_callback_register(gh, _callback, data);
}
*/
import "C"

const (
	RecvBufferSize  = 4 * 1024 * 1024
	NflogBufferSize = 4 * 1024 * 1024
	MaxQueueLogs    = 1024 * 1024
	// NflogTimeout   = 1024 // what unit?
)

// NfLog
type NfLog struct {
	// Main nflog_handle
	h *C.struct_nflog_handle
	// File descriptor for socket operations
	fd int
	// Group handle
	gh *C.struct_nflog_g_handle
	// The multicast address
	McastGroup int
	// The next expected sequence number
	seq uint32
	// Errors
	errors int64
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
	// Buffer for accumulated packets
	addPackets []AddPacket
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
	if *Debug {
		log.Println("Binding nfnetlink_log to AF_INET")
	}
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
	// Start the background process
	go nflog.Loop()
	return nflog
}

var ip6mask = net.CIDRMask(*IPv6PrefixLength, 128)

// Receive data from nflog on a callback from C
//
//export goCallback
func goCallback(_nflog unsafe.Pointer, seq uint32, payload_len C.int, payload unsafe.Pointer) {
	nflog := (*NfLog)(_nflog)

	// Get the packet into a []byte
	// NB if the C data goes away then BAD things will happen!
	// So don't keep slices from this after returning from this function
	var packet []byte
	sliceHeader := (*reflect.SliceHeader)((unsafe.Pointer(&packet)))
	sliceHeader.Cap = int(payload_len)
	sliceHeader.Len = int(payload_len)
	sliceHeader.Data = uintptr(payload)

	// Peek the IP Version out of the header
	ip_version := packet[IpVersion] >> IpVersionShift & IpVersionMask
	// log.Printf("Received %d: size %d, IPv%d", seq, payload_len, ip_version)
	if seq != 0 && seq != nflog.seq {
		nflog.errors++
		log.Printf("%d missing packets detected, %d to %d", seq-nflog.seq, seq, nflog.seq)
	}
	nflog.seq = seq + 1
	if ip_version != nflog.IpVersion {
		nflog.errors++
		log.Printf("Bad IP version: %d", ip_version)
		return
	}
	i := nflog.IpPacket
	if len(packet) < i.HeaderSize {
		nflog.errors++
		log.Printf("Short IPv%s packet %d/%d bytes", ip_version, len(packet), i.HeaderSize)
		return
	}

	var addr net.IP
	if nflog.Direction {
		addr = i.Src(packet)
	} else {
		addr = i.Dst(packet)
	}

	// Mask the address
	if ip_version == 6 {
		addr = addr.Mask(ip6mask)
	}

	nflog.addPackets = append(nflog.addPackets, AddPacket{
		Direction: nflog.Direction,
		Addr:      string(addr),
		Length:    i.Length(packet),
	})
}

// Current nflog error
func nflog_error() error {
	return syscall.Errno(C.nflog_errno)
}

// Connects to the group specified with the size
func (nflog *NfLog) makeGroup(group, size int) {
	if *Debug {
		log.Printf("Binding this socket to group %d", group)
	}
	gh := C.nflog_bind_group(nflog.h, (C.u_int16_t)(group))
	if gh == nil {
		log.Fatalf("nflog_bind_group failed: %s", nflog_error())
	}
	nflog.gh = gh

	// Set the maximum amount of logs in buffer for this group
	if C.nflog_set_qthresh(gh, MaxQueueLogs) < 0 {
		log.Fatalf("nflog_set_qthresh failed: %s", nflog_error())
	}

	// Set local sequence numbering to detect missing packets
	if C.nflog_set_flags(gh, C.NFULNL_CFG_F_SEQ) < 0 {
		log.Fatalf("nflog_set_flags failed: %s", nflog_error())
	}

	// Set buffer size large
	if C.nflog_set_nlbufsiz(gh, NflogBufferSize) < 0 {
		log.Fatalf("nflog_set_nlbufsiz: %s", nflog_error())
	}

	// Set timeout
	// Doesn't seem to make any difference and don't know the unit
	// if C.nflog_set_timeout(gh, NflogTimeout) < 0 {
	// 	log.Fatalf("nflog_set_timeout: %s", nflog_error())
	// }

	if *Debug {
		log.Printf("Setting copy_packet mode to %d bytes", size)
	}
	if C.nflog_set_mode(gh, C.NFULNL_COPY_PACKET, (C.uint)(size)) < 0 {
		log.Fatalf("nflog_set_mode failed: %s", nflog_error())
	}

	// Register the callback now we are set up
	C._callback_register(gh, unsafe.Pointer(nflog))
}

// Receive packets in a loop until quit
func (nflog *NfLog) Loop() {
	buf := make([]byte, RecvBufferSize)
	for !nflog.quit {
		nr, _, e := syscall.Recvfrom(nflog.fd, buf, 0)
		if e != nil {
			log.Printf("Recvfrom failed: %s", e)
			nflog.errors++
		} else {
			// Handle messages in packet reusing memory
			ps := <-nflog.a.returnAddPackets
			nflog.addPackets = ps[:0]
			C.nflog_handle_packet(nflog.h, (*C.char)(unsafe.Pointer(&buf[0])), (C.int)(nr))
			nflog.a.processAddPackets <- nflog.addPackets
			nflog.addPackets = nil
		}
	}

}

// Close the NfLog down
func (nflog *NfLog) Close() {
	if *Debug {
		log.Printf("Unbinding this socket (%d) from group %d", nflog.fd, nflog.McastGroup)
	}
	nflog.quit = true
	if C.nflog_unbind_group(nflog.gh) < 0 {
		log.Printf("nflog_unbind_group(%d) failed: %s", nflog.McastGroup, nflog_error())
	}
	if *Debug {
		log.Printf("Closing nflog")
	}
	if C.nflog_close(nflog.h) < 0 {
		log.Printf("nflog_close failed: %s", nflog_error())
	}
}

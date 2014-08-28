// Use cgo to interface with nflog
//
// Docs: http://www.netfilter.org/projects/libnetfilter_log/doxygen/index.html
//
// Debian packages needed:
//   apt-get install iptables-dev linux-libc-dev libnetfilter-log-dev

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
#include <inttypes.h>

// Forward definition of Go function
void processPacket(intptr_t, u_int32_t, int, void *);

// Process the incoming packet, handing it back to Go as soon as possible
static int _processPacket(struct nflog_g_handle *gh, struct nfgenmsg *nfmsg, struct nflog_data *nfd, void *data) {
	char *payload = 0;
	int payload_len = nflog_get_payload(nfd, &payload);
	u_int32_t seq = 0;
	nflog_get_seq(nfd, &seq);
	processPacket((intptr_t)data, seq, payload_len, payload);
	return 0;
 }

// Register the callback - can't be done from Go
//
// We have to register a C function _processPacket which is a thin
// shim, calling the Go function as soon as possible
static int _callback_register(struct nflog_g_handle *gh, intptr_t data) {
	return nflog_callback_register(gh, _processPacket, (void *)data);
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
	fd C.int
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
	// Mask for the IP
	Mask net.IPMask
	// Whether to apply the mask or not
	UseMask bool
	// Are we account the source or the destination address
	Direction IpDirection
	// Flavour of IP packet we are decoding
	IpPacket *IpPacketInfo
	// Accounting
	a *Accounting
	// Quit the loop
	quit chan struct{}
	// Buffer for accumulated packets
	addPackets []AddPacket
	// Index of this in nflogs - uses to pass to C instead of a Go pointer
	index int
}

// An array of NfLog pointers
type NfLogs [16]*NfLog

// A global array of all NfLogs in use
var nflogs NfLogs

// Count all active NfLogs
func (ns NfLogs) Count() int {
	active := 0
	for _, nflog := range ns {
		if nflog != nil {
			active++
		}
	}
	return active
}

// Stop all active NfLogs
func (ns NfLogs) Stop() {
	for _, nflog := range ns {
		if nflog != nil {
			nflog.Close()
		}
	}
}

// Create a new NfLog
//
// McastGroup is that specified in ip[6]tables
// IPv6 is a flag to say if it is IPv6 or not
// Direction is to monitor the source address or the dest address
func NewNfLog(McastGroup int, IpVersion byte, Direction IpDirection, MaskBits int, a *Accounting) *NfLog {
	h := C.nflog_open()
	if h == nil {
		log.Fatalf("Failed to open NFLOG: %s", strerror())
	}
	if *Debug {
		log.Println("Binding nfnetlink_log to AF_INET")
	}
	if C.nflog_bind_pf(h, C.AF_INET) < 0 {
		log.Fatalf("nflog_bind_pf failed: %s", strerror())
	}

	nflog := &NfLog{
		h:          h,
		fd:         C.nflog_fd(h),
		McastGroup: McastGroup,
		IpVersion:  IpVersion,
		Direction:  Direction,
		a:          a,
		quit:       make(chan struct{}),
	}
	for i := range nflogs {
		if nflogs[i] == nil {
			nflog.index = i
			nflogs[i] = nflog
			goto found
		}
	}
	log.Fatal("Too many filters")
found:
	switch IpVersion {
	case 4:
		nflog.IpPacket = Ip4Packet
	case 6:
		nflog.IpPacket = Ip6Packet
	default:
		log.Fatalf("Bad IP version %d", IpVersion)
	}
	addrBits := 8 * nflog.IpPacket.AddrLen
	nflog.UseMask = MaskBits < addrBits
	nflog.Mask = net.CIDRMask(MaskBits, addrBits)
	nflog.makeGroup(McastGroup, nflog.IpPacket.HeaderSize)
	// Start the background process
	go nflog.Loop()
	return nflog
}

// Receive data from nflog on a callback from C
//
//export processPacket
func processPacket(nflogIndex C.intptr_t, seq uint32, payload_len C.int, payload unsafe.Pointer) {
	nflog := nflogs[uintptr(nflogIndex)]

	// Get the packet into a []byte
	// NB if the C data goes away then BAD things will happen!
	// So don't keep slices from this after returning from this function
	var packet []byte
	sliceHeader := (*reflect.SliceHeader)((unsafe.Pointer(&packet)))
	sliceHeader.Cap = int(payload_len)
	sliceHeader.Len = int(payload_len)
	sliceHeader.Data = uintptr(payload)

	// Call a standard Go method now
	nflog.ProcessPacket(packet, seq)
}

// Process a packet
func (nflog *NfLog) ProcessPacket(packet []byte, seq uint32) {
	// log.Printf("Packet %#v", packet)
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
		log.Printf("Short IPv%d packet %d/%d bytes", ip_version, len(packet), i.HeaderSize)
		return
	}

	var addr net.IP
	if nflog.Direction {
		addr = i.Src(packet)
	} else {
		addr = i.Dst(packet)
	}

	// Mask the address
	if nflog.UseMask {
		addr = addr.Mask(nflog.Mask)
	}

	nflog.addPackets = append(nflog.addPackets, AddPacket{
		Direction: nflog.Direction,
		Addr:      string(addr),
		Length:    i.Length(packet),
	})
}

// Current nflog error
func strerror() error {
	return syscall.Errno(C.nflog_errno)
}

// Connects to the group specified with the size
func (nflog *NfLog) makeGroup(group, size int) {
	if *Debug {
		log.Printf("Binding this socket to group %d", group)
	}
	gh := C.nflog_bind_group(nflog.h, (C.u_int16_t)(group))
	if gh == nil {
		log.Fatalf("nflog_bind_group failed: %s", strerror())
	}
	nflog.gh = gh

	// Set the maximum amount of logs in buffer for this group
	if C.nflog_set_qthresh(gh, MaxQueueLogs) < 0 {
		log.Fatalf("nflog_set_qthresh failed: %s", strerror())
	}

	// Set local sequence numbering to detect missing packets
	if C.nflog_set_flags(gh, C.NFULNL_CFG_F_SEQ) < 0 {
		log.Fatalf("nflog_set_flags failed: %s", strerror())
	}

	// Set buffer size large
	if C.nflog_set_nlbufsiz(gh, NflogBufferSize) < 0 {
		log.Fatalf("nflog_set_nlbufsiz: %s", strerror())
	}

	// Set timeout
	// Doesn't seem to make any difference and don't know the unit
	// if C.nflog_set_timeout(gh, NflogTimeout) < 0 {
	// 	log.Fatalf("nflog_set_timeout: %s", strerror())
	// }

	if *Debug {
		log.Printf("Setting copy_packet mode to %d bytes", size)
	}
	if C.nflog_set_mode(gh, C.NFULNL_COPY_PACKET, (C.uint)(size)) < 0 {
		log.Fatalf("nflog_set_mode failed: %s", strerror())
	}

	// Register the callback now we are set up
	//
	// Note that we pass an index into an array, not a pointer to
	// the nflog - it isn't a good idea for C to hold pointers to
	// go objects which might move
	C._callback_register(gh, C.intptr_t(nflog.index))
}

// Receive packets in a loop until quit
func (nflog *NfLog) Loop() {
	buflen := C.size_t(RecvBufferSize)
	pbuf := C.malloc(buflen)
	if pbuf == nil {
		log.Fatal("No memory for malloc")
	}
	defer C.free(pbuf)
	for {
		nr := C.recv(nflog.fd, pbuf, buflen, 0)
		select {
		case <-nflog.quit:
			return
		default:
		}
		if nr < 0 {
			log.Printf("Recvfrom failed: %s", strerror())
			nflog.errors++
		} else {
			// Handle messages in packet reusing memory
			ps := <-nflog.a.returnAddPackets
			nflog.addPackets = ps[:0]
			C.nflog_handle_packet(nflog.h, (*C.char)(pbuf), (C.int)(nr))
			nflog.a.processAddPackets <- nflog.addPackets
			nflog.addPackets = nil
		}
	}

}

// Close the NfLog down
func (nflog *NfLog) Close() {
	close(nflog.quit)
	// Sometimes hangs and doesn't seem to be necessary
	// if *Debug {
	// 	log.Printf("Unbinding socket %d from group %d", nflog.fd, nflog.McastGroup)
	// }
	// if C.nflog_unbind_group(nflog.gh) < 0 {
	// 	log.Printf("nflog_unbind_group(%d) failed: %s", nflog.McastGroup, strerror())
	// }
	if *Debug {
		log.Printf("Closing nflog socket %d group %d", nflog.fd, nflog.McastGroup)
	}
	if C.nflog_close(nflog.h) < 0 {
		log.Printf("nflog_close failed: %s", strerror())
	}
	// Mark this index as no longer in use
	nflogs[nflog.index] = nil
}

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
#cgo LDFLAGS: -lnfnetlink -lnetfilter_log
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <libnfnetlink/libnfnetlink.h>
#include <libnetfilter_log/libnetfilter_log.h>
#include <inttypes.h>

// A record of each packet
typedef struct {
	char *payload;
	int payload_len;
	u_int32_t seq;
} packet;

// Max number of packets to collect at once
#define MAX_PACKETS (16*1024)

// A load of packets with count
typedef struct {
	int index;
	packet pkt[MAX_PACKETS];
} packets;

// Process the incoming packet putting pointers to the data to be handled by Go
static int _processPacket(struct nflog_g_handle *gh, struct nfgenmsg *nfmsg, struct nflog_data *nfd, void *data) {
	packets *ps = (packets *)data;
	if (ps->index >= MAX_PACKETS) {
		return 1;
	}
	packet *p = &ps->pkt[ps->index++];
	p->payload = 0;
	p->payload_len = nflog_get_payload(nfd, &p->payload);
	p->seq = 0;
	nflog_get_seq(nfd, &p->seq);
	return 0;
 }

// Register the callback - can't be done from Go
//
// We have to register a C function _processPacket
static int _callback_register(struct nflog_g_handle *gh, packets *data) {
	return nflog_callback_register(gh, _processPacket, data);
}
*/
import "C"

const (
	RecvBufferSize   = 4 * 1024 * 1024
	NflogBufferSize  = 128 * 1024 // Must be <= 128k (checked in kernel source)
	NfRecvBufferSize = 16 * 1024 * 1024
	NflogTimeout     = 100 // Timeout before sending data in 1/100th second
	MaxQueueLogs     = C.MAX_PACKETS - 1
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
	// Pointer to the packets
	packets *C.packets
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
	h, err := C.nflog_open()
	if h == nil || err != nil {
		log.Fatalf("Failed to open NFLOG: %s", nflogError(err))
	}
	if *Verbose {
		log.Println("Binding nfnetlink_log to AF_INET")
	}
	if rc, err := C.nflog_bind_pf(h, C.AF_INET); rc < 0 || err != nil {
		log.Fatalf("nflog_bind_pf failed: %s", nflogError(err))
	}

	nflog := &NfLog{
		h:          h,
		fd:         C.nflog_fd(h),
		McastGroup: McastGroup,
		IpVersion:  IpVersion,
		Direction:  Direction,
		a:          a,
		quit:       make(chan struct{}),
		packets:    (*C.packets)(C.malloc(C.sizeof_packets)),
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

// Process a packet
func (nflog *NfLog) ProcessPacket(packet []byte, seq uint32) AddPacket {
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
		return AddPacket{Length: -1}
	}
	i := nflog.IpPacket
	if len(packet) < i.HeaderSize {
		nflog.errors++
		log.Printf("Short IPv%d packet %d/%d bytes", ip_version, len(packet), i.HeaderSize)
		return AddPacket{Length: -1}
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

	return AddPacket{
		Direction: nflog.Direction,
		Addr:      string(addr),
		Length:    i.Length(packet),
	}
}

// Receive data from nflog stored in nflog.packets
func (nflog *NfLog) processPackets(addPackets []AddPacket) []AddPacket {
	n := int(nflog.packets.index)
	if n >= C.MAX_PACKETS {
		log.Printf("Packets buffer overflowed")
	}
	if *Verbose {
		log.Printf("%d: Processing %d packets", nflog.McastGroup, n)
	}

	var packet []byte
	sliceHeader := (*reflect.SliceHeader)((unsafe.Pointer(&packet)))

	for i := 0; i < n; i++ {
		p := &nflog.packets.pkt[i]

		// Get the packet into a []byte
		// NB if the C data goes away then BAD things will happen!
		// So don't keep slices from this after returning from this function
		sliceHeader.Cap = int(p.payload_len)
		sliceHeader.Len = int(p.payload_len)
		sliceHeader.Data = uintptr(unsafe.Pointer(p.payload))

		// Process the packet
		newAddPacket := nflog.ProcessPacket(packet, uint32(p.seq))
		if newAddPacket.Length >= 0 {
			addPackets = append(addPackets, newAddPacket)
		}
	}
	sliceHeader = nil
	packet = nil
	return addPackets
}

// Current nflog error
func nflogError(err error) error {
	if C.nflog_errno != 0 {
		return syscall.Errno(C.nflog_errno)
	}
	return err
}

// Connects to the group specified with the size
func (nflog *NfLog) makeGroup(group, size int) {
	if *Verbose {
		log.Printf("Binding this socket to group %d", group)
	}
	gh, err := C.nflog_bind_group(nflog.h, (C.u_int16_t)(group))
	if gh == nil || err != nil {
		log.Fatalf("nflog_bind_group failed: %s", nflogError(err))
	}
	nflog.gh = gh

	// Set the maximum amount of logs in buffer for this group
	if rc, err := C.nflog_set_qthresh(gh, MaxQueueLogs); rc < 0 || err != nil {
		log.Fatalf("nflog_set_qthresh failed: %s", nflogError(err))
	}

	// Set local sequence numbering to detect missing packets
	if rc, err := C.nflog_set_flags(gh, C.NFULNL_CFG_F_SEQ); rc < 0 || err != nil {
		log.Fatalf("nflog_set_flags failed: %s", nflogError(err))
	}

	// Set buffer size large
	if rc, err := C.nflog_set_nlbufsiz(gh, NflogBufferSize); rc < 0 || err != nil {
		log.Fatalf("nflog_set_nlbufsiz: %s", nflogError(err))
	}

	// Set recv buffer large - this produces ENOBUFS when too small
	if rc, err := C.nfnl_rcvbufsiz(C.nflog_nfnlh(nflog.h), NfRecvBufferSize); rc < 0 || err != nil {
		log.Fatalf("nfnl_rcvbufsiz: %s", err)
	} else {
		if rc < NfRecvBufferSize {
			log.Fatalf("nfnl_rcvbufsiz: Failed to set buffer to %d got %d", NfRecvBufferSize, rc)
		}
	}

	// Set timeout
	if rc, err := C.nflog_set_timeout(gh, NflogTimeout); rc < 0 || err != nil {
		log.Fatalf("nflog_set_timeout: %s", nflogError(err))
	}

	if *Verbose {
		log.Printf("Setting copy_packet mode to %d bytes", size)
	}
	if rc, err := C.nflog_set_mode(gh, C.NFULNL_COPY_PACKET, (C.uint)(size)); rc < 0 || err != nil {
		log.Fatalf("nflog_set_mode failed: %s", nflogError(err))
	}

	// Register the callback now we are set up
	//
	// Note that we pass a block of memory allocated by C.malloc -
	// it isn't a good idea for C to hold pointers to go objects
	// which might move
	C._callback_register(gh, nflog.packets)
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
		nr, err := C.recv(nflog.fd, pbuf, buflen, 0)
		select {
		case <-nflog.quit:
			return
		default:
		}
		if nr < 0 || err != nil {
			log.Printf("Recv failed: %s", err)
			nflog.errors++
		} else {
			// Handle messages in packet reusing memory
			ps := <-nflog.a.returnAddPackets
			nflog.packets.index = 0
			C.nflog_handle_packet(nflog.h, (*C.char)(pbuf), (C.int)(nr))
			nflog.a.processAddPackets <- nflog.processPackets(ps[:0])
		}
	}

}

// Close the NfLog down
func (nflog *NfLog) Close() {
	close(nflog.quit)
	// Sometimes hangs and doesn't seem to be necessary
	// if *Verbose {
	// 	log.Printf("Unbinding socket %d from group %d", nflog.fd, nflog.McastGroup)
	// }
	// if rc, err := C.nflog_unbind_group(nflog.gh); rc < 0 || err != nil {
	// 	log.Printf("nflog_unbind_group(%d) failed: %s", nflog.McastGroup, nflogError(err))
	// }
	if *Verbose {
		log.Printf("Closing nflog socket %d group %d", nflog.fd, nflog.McastGroup)
	}
	if rc, err := C.nflog_close(nflog.h); rc < 0 || err != nil {
		log.Printf("nflog_close failed: %s", nflogError(nil))
	}
	// Mark this index as no longer in use
	nflogs[nflog.index] = nil
	C.free(unsafe.Pointer(nflog.packets))
}

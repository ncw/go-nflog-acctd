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
	McastGroup = 1

	// 20 bytes IP Header - http://en.wikipedia.org/wiki/IPv4
	Ip4LengthOffest = 2
	Ip4SrcOffset    = 12
	Ip4DstOffset    = 16
	IpHeaderSize    = 20
)

// NfLog
type NfLog struct {
	h *C.struct_nflog_handle
	fd int
	qh *C.struct_nflog_g_handle
}

// Current nflog error
func nflog_error() error {
	return syscall.Errno(C.nflog_errno)
}

//export goCallback
func goCallback(cprefix *C.char, payload_len C.int, payload unsafe.Pointer) {
	prefix := C.GoString(cprefix)
	packet := C.GoBytes(payload, payload_len)
	log.Printf("%s: size %d", prefix, payload_len)
	// Decode the IPv4 packet parts we need
	ipv4 := packet		// FIXME IP6?
	src := ipv4[Ip4SrcOffset : Ip4SrcOffset+4]
	dst := ipv4[Ip4DstOffset : Ip4DstOffset+4]
	length := int(ipv4[Ip4LengthOffest])<<8 + int(ipv4[Ip4LengthOffest+1])
	log.Printf("IPv4 message From %s To %s Size %d", net.IP(src), net.IP(dst), length)
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

	log.Printf("Binding this socket to group %d", McastGroup)
	qh := C.nflog_bind_group(h, McastGroup)
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

	log.Println("Setting copy_packet mode")
	// FIXME header size for IPv6
	if C.nflog_set_mode(qh, C.NFULNL_COPY_PACKET, 20) < 0 {
		log.Fatal("nflog_set_mode failed: %s", nflog_error())
	}

	return &NfLog{
		h: h,
		fd: int(C.nflog_fd(h)),
		qh: qh,
	}
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
	log.Printf("Unbinding this socket from group %d", McastGroup)
	C.nflog_unbind_group(nflog.qh)
	log.Printf("Closing NFLOG")
	C.nflog_close(nflog.h)
}

// Package dnsproxy implements the IPv4 interception experiment. It does not
// discover or substitute an upstream: each transaction carries its destination.
package dnsproxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/miekg/dns"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

type Handler func(context.Context, net.IP, string, *dns.Msg) (*dns.Msg, error)
type Server struct {
	udp     *net.UDPConn
	tcp     net.Listener
	mode    string
	handle  Handler
	slots   chan struct{}
	wg      sync.WaitGroup
	readers sync.WaitGroup
}

func Start(ctx context.Context, address, mode string, handle Handler) (*Server, error) {
	if mode != "dnat" && mode != "tproxy" && mode != "hybrid" {
		return nil, fmt.Errorf("invalid interception mode %q", mode)
	}
	lc := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
		var e error
		err := raw.Control(func(fd uintptr) {
			e = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_RECVORIGDSTADDR, 1)
			if e == nil && mode != "dnat" {
				e = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1)
			}
		})
		if err != nil {
			return err
		}
		return e
	}}
	pc, err := lc.ListenPacket(ctx, "udp4", address)
	if err != nil {
		return nil, err
	}
	ln, err := lc.Listen(ctx, "tcp4", address)
	if err != nil {
		pc.Close()
		return nil, err
	}
	s := &Server{udp: pc.(*net.UDPConn), tcp: ln, mode: mode, handle: handle, slots: make(chan struct{}, 128)}
	go func() { <-ctx.Done(); s.udp.Close(); s.tcp.Close() }()
	s.readers.Add(2)
	go func() { defer s.readers.Done(); s.readUDP(ctx) }()
	go func() { defer s.readers.Done(); s.readTCP(ctx) }()
	return s, nil
}
func (s *Server) Close() { s.udp.Close(); s.tcp.Close(); s.readers.Wait(); s.wg.Wait() }
func (s *Server) acquire() bool {
	select {
	case s.slots <- struct{}{}:
		s.wg.Add(1)
		return true
	default:
		return false
	}
}
func (s *Server) release() { <-s.slots; s.wg.Done() }
func OriginalUDP(oob []byte) (*net.UDPAddr, error) {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, err
	}
	for _, m := range msgs {
		if m.Header.Level == unix.SOL_IP && m.Header.Type == unix.IP_ORIGDSTADDR && len(m.Data) >= 8 {
			return &net.UDPAddr{IP: net.IPv4(m.Data[4], m.Data[5], m.Data[6], m.Data[7]), Port: int(binary.BigEndian.Uint16(m.Data[2:4]))}, nil
		}
	}
	return nil, errors.New("missing original destination")
}
func originalTCP(c *net.TCPConn, mode string) (string, error) {
	if mode == "tproxy" || (mode == "hybrid" && c.LocalAddr().(*net.TCPAddr).Port == 53) {
		return c.LocalAddr().String(), nil
	}
	raw, err := c.SyscallConn()
	if err != nil {
		return "", err
	}
	var sa unix.RawSockaddrInet4
	size := uint32(unsafe.Sizeof(sa))
	var errno syscall.Errno
	err = raw.Control(func(fd uintptr) {
		_, _, errno = syscall.Syscall6(unix.SYS_GETSOCKOPT, fd, unix.SOL_IP, 80, uintptr(unsafe.Pointer(&sa)), uintptr(unsafe.Pointer(&size)), 0)
	})
	if err != nil {
		return "", err
	}
	if errno != 0 {
		return "", errno
	}
	port := *(*[2]byte)(unsafe.Pointer(&sa.Port))
	return net.JoinHostPort(net.IP(sa.Addr[:]).String(), fmt.Sprint(binary.BigEndian.Uint16(port[:]))), nil
}
func (s *Server) answer(ctx context.Context, ip net.IP, dest string, wire []byte, datagram bool) []byte {
	q := new(dns.Msg)
	if q.Unpack(wire) != nil {
		return nil
	}
	reply, err := s.handle(ctx, ip, dest, q)
	if err != nil {
		reply = new(dns.Msg)
		reply.SetRcode(q, dns.RcodeServerFailure)
	}
	if reply == nil {
		return nil
	}
	if datagram {
		limit := 512
		if opt := q.IsEdns0(); opt != nil {
			limit = int(opt.UDPSize())
			if limit < 512 {
				limit = 512
			}
			if limit > 1232 {
				limit = 1232
			}
		}
		reply.Truncate(limit)
	}
	out, err := reply.Pack()
	if err != nil {
		return nil
	}
	return out
}
func (s *Server) readUDP(ctx context.Context) {
	for {
		buf := make([]byte, 65535)
		oob := make([]byte, 128)
		n, on, flags, peer, err := s.udp.ReadMsgUDP(buf, oob)
		if err != nil {
			return
		}
		if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
			continue
		}
		dst, err := OriginalUDP(oob[:on])
		local := dst
		nat := s.mode == "dnat" || (s.mode == "hybrid" && err == nil && dst.Port == 50052)
		if err == nil && nat {
			dst, err = originalNATUDP(peer, dst)
		}
		if err != nil || dst.Port != 53 || !s.acquire() {
			continue
		}
		go func(b []byte, peer, dst, local *net.UDPAddr, nat bool) {
			defer s.release()
			out := s.answer(ctx, peer.IP, dst.String(), b, true)
			if len(out) == 0 {
				return
			}
			if nat {
				// Select the translated local address so conntrack reverses the DNAT.
				s.udp.WriteMsgUDP(out, (&ipv4.ControlMessage{Src: local.IP}).Marshal(), peer)
				return
			}
			// The transparent reply must have the source the client queried.
			d := net.Dialer{Timeout: time.Second, LocalAddr: &net.IPAddr{IP: dst.IP}, Control: func(_, _ string, r syscall.RawConn) error {
				var e error
				err := r.Control(func(fd uintptr) {
					e = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1)
					if e == nil {
						e = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
					}
				})
				if err != nil {
					return err
				}
				return e
			}}
			// A raw UDP reply avoids binding port 53 already owned by NodeLocal.
			c, err := d.DialContext(ctx, "ip4:udp", peer.IP.String())
			if err == nil {
				c.SetWriteDeadline(time.Now().Add(time.Second))
				c.Write(udpDatagram(dst, peer, out))
				c.Close()
			}
		}(buf[:n], peer, dst, local, nat)
	}
}
func (s *Server) readTCP(ctx context.Context) {
	for {
		c, err := s.tcp.Accept()
		if err != nil {
			return
		}
		if !s.acquire() {
			c.Close()
			continue
		}
		go func(c *net.TCPConn) {
			defer s.release()
			defer c.Close()
			dest, err := originalTCP(c, s.mode)
			if err != nil {
				return
			}
			for {
				c.SetDeadline(time.Now().Add(5 * time.Second))
				var size [2]byte
				if _, err = io.ReadFull(c, size[:]); err != nil {
					return
				}
				n := int(binary.BigEndian.Uint16(size[:]))
				if n == 0 {
					return
				}
				buf := make([]byte, n)
				if _, err = io.ReadFull(c, buf); err != nil {
					return
				}
				out := s.answer(ctx, c.RemoteAddr().(*net.TCPAddr).IP, dest, buf, false)
				if len(out) == 0 {
					return
				}
				binary.BigEndian.PutUint16(size[:], uint16(len(out)))
				if _, err = c.Write(append(size[:], out...)); err != nil {
					return
				}
			}
		}(c.(*net.TCPConn))
	}
}

// shortcut: the DNAT comparison uses a conntrack dump, not a production-scale
// indexed lookup. Replace with an exact netlink GET before selecting DNAT for GA.
// IP_RECVORIGDSTADDR alone reports the post-DNAT destination on this kernel.
func originalNATUDP(peer, local *net.UDPAddr) (*net.UDPAddr, error) {
	flows, err := netlink.ConntrackTableList(netlink.ConntrackTable, netlink.FAMILY_V4)
	if err != nil {
		return nil, err
	}
	if len(flows) > 8192 {
		return nil, fmt.Errorf("conntrack comparison budget exceeded")
	}
	var result *net.UDPAddr
	for _, f := range flows {
		if f.Forward.Protocol != 17 || !f.Forward.SrcIP.Equal(peer.IP) || int(f.Forward.SrcPort) != peer.Port || !f.Reverse.SrcIP.Equal(local.IP) || int(f.Reverse.SrcPort) != local.Port {
			continue
		}
		if result != nil {
			return nil, fmt.Errorf("ambiguous original DNS destination")
		}
		result = &net.UDPAddr{IP: f.Forward.DstIP, Port: int(f.Forward.DstPort)}
	}
	if result == nil {
		return nil, fmt.Errorf("original DNS conntrack entry missing")
	}
	return result, nil
}

// udpDatagram includes a pseudo-header checksum; the kernel supplies the IPv4 header.
func udpDatagram(src, dst *net.UDPAddr, payload []byte) []byte {
	b := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(b[0:2], uint16(src.Port))
	binary.BigEndian.PutUint16(b[2:4], uint16(dst.Port))
	binary.BigEndian.PutUint16(b[4:6], uint16(len(b)))
	copy(b[8:], payload)
	pseudo := make([]byte, 12+len(b))
	copy(pseudo[0:4], src.IP.To4())
	copy(pseudo[4:8], dst.IP.To4())
	pseudo[9] = 17
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(b)))
	copy(pseudo[12:], b)
	var sum uint32
	for i := 0; i+1 < len(pseudo); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pseudo[i : i+2]))
	}
	if len(pseudo)%2 == 1 {
		sum += uint32(pseudo[len(pseudo)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	check := ^uint16(sum)
	if check == 0 {
		check = 0xffff
	}
	binary.BigEndian.PutUint16(b[6:8], check)
	return b
}

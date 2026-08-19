package guardreality

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/LatticeNet/lattice-sdk/model"
)

// Listening sockets, read from /proc rather than shelled out to ss or netstat.
//
// A firewall review is only as good as the list of things actually listening,
// and that list has to be collectable on a minimal box: ss and lsof are not
// installed everywhere, and running them as root to parse their output is a
// worse dependency than reading the files the kernel already exposes.
//
// The mapping from socket to process is best-effort by design. It needs to walk
// every /proc/<pid>/fd, which requires root and races with processes exiting;
// when it cannot see an owner the listener is still reported, because "port 8443
// is open and I do not know who has it" is exactly the finding an operator
// needs, not a reason to drop the row.

const (
	// tcpStateListen is the value /proc/net/tcp uses for LISTEN.
	tcpStateListen = "0A"
	// maxListeners bounds a report. The server caps it too; stopping here keeps
	// a box with thousands of sockets from building a payload it cannot send.
	maxListeners = 256
)

type procSocket struct {
	protocol string
	address  string
	port     int
	inode    string
}

// Listeners returns the sockets accepting connections on this host.
func Listeners() []model.GuardListener {
	sockets := make([]procSocket, 0, 64)
	for _, source := range []struct {
		path     string
		protocol string
		// UDP has no LISTEN state; a bound UDP socket is the listener.
		listenOnly bool
	}{
		{"/proc/net/tcp", "tcp", true},
		{"/proc/net/tcp6", "tcp", true},
		{"/proc/net/udp", "udp", false},
		{"/proc/net/udp6", "udp", false},
	} {
		sockets = append(sockets, parseProcNet(source.path, source.protocol, source.listenOnly)...)
	}
	owners := socketOwners()

	seen := map[string]bool{}
	out := make([]model.GuardListener, 0, len(sockets))
	for _, socket := range sockets {
		key := socket.protocol + "|" + socket.address + "|" + strconv.Itoa(socket.port)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, model.GuardListener{
			Protocol: socket.protocol,
			Port:     socket.port,
			Address:  socket.address,
			Process:  owners[socket.inode],
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		if out[i].Protocol != out[j].Protocol {
			return out[i].Protocol < out[j].Protocol
		}
		return out[i].Address < out[j].Address
	})
	if len(out) > maxListeners {
		out = out[:maxListeners]
	}
	return out
}

func parseProcNet(path, protocol string, listenOnly bool) []procSocket {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	out := make([]procSocket, 0, 32)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		// sl local_address rem_address st ... — the header line has no colon in
		// field 1 and falls out here.
		if len(fields) < 4 || !strings.Contains(fields[1], ":") {
			continue
		}
		if listenOnly && fields[3] != tcpStateListen {
			continue
		}
		address, port, ok := parseProcAddress(fields[1])
		if !ok {
			continue
		}
		inode := ""
		if len(fields) >= 10 {
			inode = fields[9]
		}
		out = append(out, procSocket{protocol: protocol, address: address, port: port, inode: inode})
	}
	return out
}

// parseProcAddress decodes the hex "address:port" /proc uses. Bytes are
// little-endian per 32-bit word, which is why this cannot be a plain hex decode.
func parseProcAddress(value string) (string, int, bool) {
	rawAddr, rawPort, ok := strings.Cut(value, ":")
	if !ok {
		return "", 0, false
	}
	port, err := strconv.ParseInt(rawPort, 16, 32)
	if err != nil || port < 0 || port > 65535 {
		return "", 0, false
	}
	bytes, err := hex.DecodeString(rawAddr)
	if err != nil || len(bytes)%4 != 0 || len(bytes) == 0 {
		return "", 0, false
	}
	for i := 0; i < len(bytes); i += 4 {
		bytes[i], bytes[i+3] = bytes[i+3], bytes[i]
		bytes[i+1], bytes[i+2] = bytes[i+2], bytes[i+1]
	}
	ip := net.IP(bytes)
	if len(bytes) == 16 {
		// A v4-mapped v6 socket is the same listener an operator sees as v4.
		if mapped := ip.To4(); mapped != nil {
			ip = mapped
		}
	}
	return ip.String(), int(port), true
}

// socketOwners maps socket inode to a process name. Missing entries are normal:
// without root most /proc/<pid>/fd directories are unreadable.
func socketOwners() map[string]string {
	owners := map[string]string{}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return owners
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid := entry.Name()
		if _, err := strconv.Atoi(pid); err != nil {
			continue
		}
		fds, err := os.ReadDir(filepath.Join("/proc", pid, "fd"))
		if err != nil {
			continue
		}
		name := ""
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join("/proc", pid, "fd", fd.Name()))
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			inode := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
			if inode == "" {
				continue
			}
			if name == "" {
				name = processName(pid)
			}
			if _, exists := owners[inode]; !exists {
				owners[inode] = name
			}
		}
	}
	return owners
}

func processName(pid string) string {
	raw, err := os.ReadFile(filepath.Join("/proc", pid, "comm"))
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%s(%s)", strings.TrimSpace(string(raw)), pid)
}

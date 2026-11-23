package neighbours

import (
	"bufio"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/emit"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/fsread"
	"github.com/arseniteio/oscompliance-ens-wazuh/catalog/fact"
)

type Config struct {
	ARP string
}

var Default = Config{ARP: "/proc/net/arp"}

const unresolved = "00:00:00:00:00:00"

// atfComplete is ATF_COM in the flags of /proc/net/arp: the MAC is resolved.
// Permanent entries (ATF_PERM) carry it too, as 0x6.
const atfComplete = 0x2

// QEMU gives these MACs to a NIC without an address; a VM removed long ago can leave one in the table.
var qemuPlaceholders = []string{"52:54:00:00:00:00", "52:54:00:00:00:01"}

func ignored(flags, mac string) bool {
	n, err := strconv.ParseUint(strings.TrimPrefix(flags, "0x"), 16, 32)
	return err != nil || n&atfComplete == 0 || NotAHost(mac)
}

// NotAHost tells a lowercase, colon-separated MAC that names no neighbour:
// unresolved, broadcast, multicast or a QEMU placeholder.
func NotAHost(mac string) bool {
	return mac == unresolved || slices.Contains(qemuPlaceholders, mac) ||
		mac == "ff:ff:ff:ff:ff:ff" || strings.HasPrefix(mac, "01:00:5e:") || strings.HasPrefix(mac, "33:33:")
}

func Sort(neighbours []fact.Neighbour) {
	sort.Slice(neighbours, func(i, j int) bool {
		if neighbours[i].IP != neighbours[j].IP {
			return neighbours[i].IP < neighbours[j].IP
		}
		return neighbours[i].Interface < neighbours[j].Interface
	})
}

func Collect(e *emit.Emitter, cfg Config) error {

	s := fact.NeighbourSnapshot{Envelope: e.Envelope(fact.NeighbourSnapshotFact), Status: fact.SourceRead, Neighbours: []fact.Neighbour{}}

	data, err := fsread.ReadFile(cfg.ARP)
	if err != nil {
		s.Status, s.Error = fact.SourceUnreadable, err.Error()
		return e.Emit(s)
	}

	s.Neighbours = parse(string(data))
	return e.Emit(s)
}

func parse(table string) []fact.Neighbour {

	seen := map[string]bool{}
	out := []fact.Neighbour{}

	lines := bufio.NewScanner(strings.NewReader(table))
	for header := true; lines.Scan(); header = false {
		f := strings.Fields(lines.Text())
		if header || len(f) < 6 {
			continue
		}
		ip, flags, mac, device := f[0], f[2], strings.ToLower(f[3]), f[5]
		if ignored(flags, mac) || seen[ip+device] {
			continue
		}
		seen[ip+device] = true
		out = append(out, fact.Neighbour{IP: ip, MAC: mac, Interface: device})
	}

	Sort(out)
	return out
}

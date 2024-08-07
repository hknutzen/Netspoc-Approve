package linux

import (
	"sort"
	"strconv"
	"strings"

	"github.com/hknutzen/Netspoc-Approve/go/pkg/device"
)

type tables map[string]chains
type chains map[string]*chain
type chain struct {
	policy string
	rules  []rule
}
type rule struct {
	orig   string
	pairs  map[string]string
	append bool
}

func (s *State) ParseConfig(data []byte, fName string,
) (device.DeviceConfig, error) {
	var rLines, tLines []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		if strings.HasPrefix(line, "ip route") {
			rLines = append(rLines, line)
		} else {
			tLines = append(tLines, line)
		}
	}
	return &config{
		routes:   rLines,
		iptables: s.parseIPTables(tLines),
	}, nil
}

func (s *State) parseIPTables(lines []string) tables {
	tb := make(tables)
	var cMap chains
	appendRule := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		switch line[0] {
		case '*':
			// *filter
			name := line[1:]
			cMap = make(chains)
			tb[name] = cMap
			appendRule = false
		case ':':
			// :INPUT ACCEPT [68024:74200042]
			// :e0_in - [0:0]
			if cMap == nil {
				device.Abort("Found chain policy outside of table: %q", line)
			}
			words := strings.Fields(line[1:])
			if len(words) >= 2 {
				name, policy := words[0], words[1]
				cMap[name] = &chain{policy: policy}
			}
		case '-':
			// -A INPUT -s 10.1.2.3 -p tcp ! --syn -j ACCEPT
			// -A INPUT -j ACCEPT -p TCP ! --tcp-flags FIN,SYN,RST,ACK SYN

			// Store rule as map and additionally as original string.
			// Allow zero, one or more arguments after key.
			// '!' may occur before or after the key,
			// but only after key, if at least one argument.
			if cMap == nil {
				device.Abort("Found rule outside of table: %q", line)
			}
			words := strings.Fields(line)
			if words[0] != "-A" {
				device.Abort("Unsupported command %q", words[0])
			}
			if len(words) < 2 {
				device.Abort("Incomplete command %q", line)
			}
			name := words[1]
			ch := cMap[name]
			if ch == nil {
				device.Abort("Must define policy before adding rules of chain %q",
					name)
			}
			words = words[2:]
			pairs := make(map[string]string)
			for len(words) > 0 {
				negate := ""
				// Key may be preceeded by negation.
				if words[0] == "!" {
					negate = "!"
					words = words[1:]
					if len(words) == 0 {
						device.Abort("Unexpected trailing '!' in line\n %s", line)
					}
				}
				key := words[0]
				words = words[1:]
				// First argument may be preceeded by negation.
				if len(words) >= 2 && words[0] == "!" && words[1][0] != '-' {
					negate = "!"
					words = words[1:]
				}
				// Read arguments up to next key.
				var args []string
				for len(words) > 0 && words[0][0] != '-' && words[0] != "!" {
					args = append(args, words[0])
					words = words[1:]
				}
				v := negate + strings.Join(args, " ")

				// Hard coded special case:
				// ! --tcp-flags FIN,SYN,RST,ACK SYN ==> ! --syn
				if key == "--tcp-flags" && v == "!FIN,SYN,RST,ACK SYN" {
					key = "--syn"
					v = "!"
				}
				pairs[key] = v
			}
			normalizeIPTables(pairs)
			ch.rules = append(ch.rules,
				rule{orig: line, pairs: pairs, append: appendRule})
		default:
			switch line {
			case "[APPEND]":
				appendRule = true
			case "COMMIT":
				// ignore
			default:
				device.Abort("Unknown command: %q", line)
			}
		}
	}
	return tb
}

// Normalize values of iptables rules.
func normalizeIPTables(pairs map[string]string) {
	// Ignore match option for standard protocols.
	if v, found := pairs["-m"]; found {
		proto := pairs["-p"]
		if strings.ToLower(v) == strings.ToLower(proto) {
			delete(pairs, "-m")
		}
	}
	// --set-xmark is equivalent to --set-mark
	// for default mask /0xffffffff
	if v, found := pairs["--set-xmark"]; found {
		_, mask, found := strings.Cut(v, "/")
		if !found || strings.ToLower(mask) == "0xffffffff" {
			delete(pairs, "--set-xmark")
			pairs["--set-mark"] = v
		}
	}
	for k, v := range pairs {
		switch k {
		case "-s", "-d":
			if before, found := strings.CutSuffix(v, "/32"); found {
				v = before
			}
		case "-p":
			// Lowercase protocol names.
			v = strings.ToLower(v)
			// Use numbers for some protocol names.
			switch v {
			case "vrrp":
				v = "112"
			case "ipv6-icmp":
				v = "58"
			}
		case "--dport":
			v = strings.TrimLeft(v, "0")
			if before, found := strings.CutSuffix(v, ":65535"); found {
				v = before + ":"
			}
		case "--state":
			// RELATED,ESTABLISHED -> ESTABLISHED,RELATED
			l := strings.Split(v, ",")
			sort.Strings(l)
			v = strings.Join(l, ",")
		case "--set-mark":
			v = strings.ToLower(v)
			// Ignore default mask.
			v, _ = strings.CutSuffix(v, "/0xffffffff")
			// Convert from hex to decimal.
			if i, err := strconv.ParseInt(v, 0, 32); err == nil {
				v = strconv.FormatInt(i, 10)
			}
		case "--log-level":
			if v == "debug" {
				v = "7"
			}
		}
		pairs[k] = v
	}
}

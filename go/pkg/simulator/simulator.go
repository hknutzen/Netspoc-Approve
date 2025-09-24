package simulator

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"sync/atomic"

	expect "github.com/tailscale/goexpect"
)

// Simulator implements a simple Cisco-like CLI simulator driven by a scenario.
// It writes CRLF and echoes input, supports <!> interactive markers and banners.
// Prompts are emitted as "DEVICE#".

type Simulator struct {
	device   string
	preamble string
	eof      bool
	cmd2out  map[string]string
	cmd2bCmd map[string]string
}

// SimulatorFromScenario parses the scenario text and creates a Simulator.
func SimulatorFromScenario(device, scenarioText string) (*Simulator, error) {
	// Delimiter: a line starting with '#', optional spaces, capture the command
	// text, optional spaces, then a newline. Use multi-line mode.
	delim := regexp.MustCompile(`(?m)^#[ ]*(.*)[ ]*\n`)

	// Split into preamble, cmd-a, output-a, cmd-b, output-b, ...
	parts := delim.Split(scenarioText, -1)

	// Extract all command lines captured by the delimiter.
	matches := delim.FindAllStringSubmatch(scenarioText, -1)

	// Preamble is the text before the first '#'-command section. Remove trailing
	// newline to allow prompts at the end of preamble without adding another LF.
	preamble := ""
	if len(parts) > 0 {
		preamble = parts[0]
		if preamble != "" {
			preamble = strings.TrimRight(preamble, "\r\n")
		}
	}

	// Special case: If preamble ends with the literal "EOF", trim it and exit
	// after sending the preamble.
	eof := false
	if preamble != "" && strings.HasSuffix(preamble, "EOF") {
		eof = true
		preamble = strings.TrimSuffix(preamble, "EOF")
	}

	// Build mapping from command text to its output block.
	cmd2out := make(map[string]string)
	for i := 0; i < len(matches) && i+1 < len(parts); i++ {
		cmd := strings.TrimSpace(matches[i][1])
		out := parts[i+1]
		cmd2out[cmd] = out
	}

	// Banner handling:
	// - Keys that are exactly "\MARKER/" define a banner with associated text.
	// - Markers embedded in command lines are replaced by the banner text in the
	//   echoed (garbled) command, but lookup uses the command with the marker
	//   removed.

	// Banner definition keys match exactly "\word/"
	reBannerKey := regexp.MustCompile(`^\\\w+/$`)
	// Markers embedded within a command line: "\word/"
	reBannerMarker := regexp.MustCompile(`\\\w+/`)
	// If banner output ends with "#\n" or "#\r\n", drop the newline only, keep '#'
	rePromptNL := regexp.MustCompile(`#\r?\n$`)

	// Collect banner definitions and remove them from normal command map.
	banner2out := make(map[string]string)
	for k, v := range cmd2out {
		if reBannerKey.MatchString(k) {
			// Special case: trim trailing newline if prompt is part of output
			v = rePromptNL.ReplaceAllString(v, "#")
			banner2out[k] = v
			delete(cmd2out, k)
		}
	}

	// Replace banner markers in command keys and build garbled echo map.
	cmd2bCmd := make(map[string]string)
	// Snapshot keys to safely mutate the map while iterating.
	keys := make([]string, 0, len(cmd2out))
	for k := range cmd2out {
		keys = append(keys, k)
	}
	for _, orig := range keys {
		// Replace all banner markers within the command key.
		markers := reBannerMarker.FindAllStringIndex(orig, -1)
		if markers == nil {
			continue
		}
		garbled := orig
		stripped := orig
		// Process markers from left to right, adjusting offsets as we replace.
		offsetG := 0
		offsetS := 0
		for _, m := range markers {
			start, end := m[0], m[1]
			marker := orig[start:end]
			bText, ok := banner2out[marker]
			if !ok {
				return nil, fmt.Errorf("unknown banner marker: %s", marker)
			}
			// In garbled version, replace marker with banner text.
			gs := start + offsetG
			ge := end + offsetG
			insert := bText
			garbled = garbled[:gs] + insert + garbled[ge:]
			offsetG += len(insert) - (end - start)
			// In stripped version, remove the marker entirely
			ss := start + offsetS
			se := end + offsetS
			stripped = stripped[:ss] + stripped[se:]
			offsetS -= (end - start)
		}
		out := cmd2out[orig]
		delete(cmd2out, orig)
		cmd2out[stripped] = out
		cmd2bCmd[stripped] = garbled
	}

	return &Simulator{
		device:   device,
		preamble: preamble,
		eof:      eof,
		cmd2out:  cmd2out,
		cmd2bCmd: cmd2bCmd,
	}, nil
}

// sendLine writes a line to out, converting LF to CRLF and processing <!> markers.
func (s *Simulator) sendLine(line string, reader *bufio.Reader, out io.Writer) error {
	line = strings.ReplaceAll(line, "\n", "\r\n")
	// Split by the interactive marker "<!>"
	parts := strings.Split(line, "<!>")
	for i, part := range parts {
		if _, err := io.WriteString(out, part); err != nil {
			return err
		}

		// If not the last part, wait for user to press Enter.
		if i < len(parts)-1 {
			// If the writer supports Flush(), ensure earlier buffered data
			// is sent before we block waiting for input (important when out
			// is a bufferingWriter).
			if f, ok := out.(interface{ Flush() error }); ok {
				_ = f.Flush()
			}

			input, err := reader.ReadString('\n')
			if err != nil {
				return nil
			}
			// Echo what the user typed, including their newline.
			if err := s.sendLine(input, reader, out); err != nil {
				return err
			}
		}
	}
	return nil
}

// bufferingWriter accumulates writes in-memory and can flush them in one
// atomic write to the underlying writer.
type bufferingWriter struct {
	final io.Writer
	buf   bytes.Buffer
}

func (b *bufferingWriter) Write(p []byte) (int, error) { return b.buf.Write(p) }

func (b *bufferingWriter) Flush() error {
	if b.buf.Len() == 0 {
		return nil
	}
	_, err := b.final.Write(b.buf.Bytes())
	b.buf.Reset()
	return err
}

// Run executes the simulator session reading from in and writing to out until exit.
func (s *Simulator) Run(in io.Reader, out io.Writer) error {
	// Prepare buffered reader for stdin
	reader := bufio.NewReader(in)

	// Send preamble on startup (may contain <!> markers)
	if s.preamble != "" {
		pre := s.preamble
		if err := s.sendLine(pre, reader, out); err != nil {
			return err
		}
	}
	if s.eof {
		// Early exit after preamble, as requested by scenario
		return nil
	}

	// Main loop: read a command, echo it (possibly garbled), print
	// associated output, then the device prompt.
	for {
		// Read a single command line from stdin
		input, err := reader.ReadString('\n')
		if err != nil {
			return nil
		}
		// Trim both CR and LF to normalize input command string
		cmd := strings.TrimRight(input, "\r\n")

		// Ignore leading "do " for matching, but remember it for echoing
		lookup := strings.TrimPrefix(cmd, "do ")
		hasDo := len(cmd) != len(lookup)

		// Use a per-command buffering writer so echo+output+prompt are flushed
		// together in one write, avoiding interleaving races.
		bw := &bufferingWriter{final: out}

		// Echo command: if a banner applies, echo the garbled variant
		if b, ok := s.cmd2bCmd[lookup]; ok {
			if hasDo {
				b = "do " + b
			}
			if err := s.sendLine(b+"\n", reader, bw); err != nil {
				return err
			}
		} else {
			if err := s.sendLine(cmd+"\n", reader, bw); err != nil {
				return err
			}
		}

		// Exit immediately after echo if the command is "exit"
		if lookup == "exit" {
			return nil
		}

		// If there is known output for this command, send it now
		if outText, ok := s.cmd2out[lookup]; ok {
			if err := s.sendLine(outText, reader, bw); err != nil {
				return err
			}
		}

		// Finally, print the device prompt (no line ending in scenario)
		if err := s.sendLine(s.device+"#", reader, bw); err != nil {
			return err
		}

		// Flush the buffered output for the entire command atomically.
		if err := bw.Flush(); err != nil {
			return err
		}
	}
}

// trackedReader wraps a reader and records when EOF has been seen.
type trackedReader struct {
	inner io.Reader
	eof   int32
}

func (t *trackedReader) Read(p []byte) (int, error) {
	n, err := t.inner.Read(p)
	if err == io.EOF {
		atomic.StoreInt32(&t.eof, 1)
	}
	return n, err
}

func (t *trackedReader) EOF() bool { return atomic.LoadInt32(&t.eof) == 1 }

// SpawnScenarioExpecter returns an expecter connected to an in-process simulator.
func SpawnScenarioExpecter(device, scenario string, timeout time.Duration, opts ...expect.Option) (*expect.GExpect, <-chan error, error) {
	sim, err := SimulatorFromScenario(device, scenario)
	if err != nil {
		return nil, nil, err
	}
	// Pipe for expect to write into simulator
	simInR, simInW := io.Pipe()
	// Pipe for simulator to write into expect
	simOutR, simOutW := io.Pipe()

	// Wrap simOutR to track when EOF has been seen
	tr := &trackedReader{inner: simOutR}
	// Channel to report when simulator has ended
	resCh := make(chan error, 1)
	var alive int32 = 1
	var deadAt int64 = 0

	// Run the simulator in a goroutine
	go func() {
		defer simOutW.Close()
		// When the simulator finishes, signal via channel
		err := sim.Run(simInR, simOutW)
		atomic.StoreInt32(&alive, 0)
		atomic.StoreInt64(&deadAt, time.Now().UnixNano())
		resCh <- err
	}()

	// Read graceful shutdown window from env (milliseconds). Default 20ms.
	graceMs := int64(20)
	if v := os.Getenv("SIMULATOR_SHUTDOWN_GRACE_MS"); v != "" {
		if i, err := strconv.ParseInt(v, 10, 64); err == nil && i >= 0 {
			graceMs = i
		}
	}

	ge, ch, err := expect.SpawnGeneric(&expect.GenOptions{

		// Input to simulator (from expect)
		In: simInW,
		// Output from simulator (to expect)
		Out: tr,
		// Wait for simulator to end
		Wait: func() error { return <-resCh },
		Close: func() error {
			// Close immediately; Check() will allow a short grace period
			// after simulator death so in-flight writes can finish.
			_ = simInW.Close()
			return nil
		},

		// Report not running only after simulator ended AND output has been drained.
		Check: func() bool {
			// If simulator still alive or output not drained, report running.
			if atomic.LoadInt32(&alive) != 0 || !tr.EOF() {
				return true
			}
			// If we reached here, simulator ended and output drained. Allow a
			// small grace window after death to avoid races with in-flight
			// writes. If deadAt is not set, be conservative and report running.
			da := atomic.LoadInt64(&deadAt)
			if da == 0 {
				return true
			}
			if time.Since(time.Unix(0, da)) < time.Duration(graceMs)*time.Millisecond {
				return true
			}
			return false
		},
	}, timeout, opts...)
	if err != nil {
		return nil, nil, err
	}
	return ge, ch, nil
}

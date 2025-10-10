package ciscosim

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
)

// Simulator implements a simple Cisco-like CLI simulator driven by a scenario.
// It writes CRLF and echoes input, supports <!> interactive markers and
// banners.
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
				return nil, fmt.Errorf(
					"unknown banner marker: %s", marker,
				)
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

// fakeExpecter implements the expecter interface using a bytes.Buffer to store
// output and simulate command responses synchronously.
type fakeExpecter struct {
	sim             *Simulator
	buffer          bytes.Buffer
	lastReadIdx     int
	done            bool
	timeout         time.Duration
	waitingForInput bool     // True when we've hit a <!> marker and are waiting for Send()
	inputSegments   []string // Current segments split by <!>
	inputIdx        int      // Current position in input segments
	needsPrompt     bool     // True if we need to add prompt after input segments complete
}

// newFakeExpecter creates a fake expecter backed by the simulator.
func newFakeExpecter(
	device, scenario string,
	timeout time.Duration,
) (*fakeExpecter, func(), error) {
	sim, err := SimulatorFromScenario(device, scenario)
	if err != nil {
		return nil, nil, err
	}

	f := &fakeExpecter{
		sim:     sim,
		timeout: timeout,
	}

	// Process preamble immediately
	if sim.preamble != "" {
		f.sendText(sim.preamble, false)
	}

	if sim.eof {
		f.done = true
	}

	cleanup := func() {}
	return f, cleanup, nil
}

// sendText processes text for output, handling <!> markers and CRLF conversion.
// If the text contains <!> markers, it writes the first segment and sets up
// for interactive input. Otherwise, it writes all text to the buffer.
func (f *fakeExpecter) sendText(text string, addPrompt bool) {
	// Process output, replacing LF with CRLF
	text = strings.ReplaceAll(text, "\n", "\r\n")
	// Handle <!> markers - these indicate interactive prompts
	parts := strings.Split(text, "<!>")
	if len(parts) > 1 {
		// Write first part
		f.buffer.WriteString(parts[0])
		// Mark that we're waiting for input
		f.waitingForInput = true
		f.inputSegments = parts
		f.inputIdx = 0
		f.needsPrompt = addPrompt
	} else {
		f.buffer.WriteString(text)
	}
}

// Expect waits for a regex pattern to match in the buffer.
func (f *fakeExpecter) Expect(
	re *regexp.Regexp,
	timeout time.Duration,
) (string, []string, error) {
	data := f.buffer.String()
	if loc := re.FindStringIndex(data[f.lastReadIdx:]); loc != nil {
		end := f.lastReadIdx + loc[1]
		out := data[f.lastReadIdx:end]
		f.lastReadIdx = end
		return out, nil, nil
	}

	// If we're done (EOF or closed), return "Process not running" error
	if f.done {
		remaining := data[f.lastReadIdx:]
		return remaining, nil, fmt.Errorf("expect: Process not running")
	}

	// In a synchronous fake expecter, if pattern doesn't match, timeout immediately
	remaining := data[f.lastReadIdx:]
	return remaining, nil, fmt.Errorf(
		"expect: timer expired after %v seconds", timeout.Seconds(),
	)
}

// Send sends a command to the simulator.
func (f *fakeExpecter) Send(cmd string) error {
	if f.done {
		return nil
	}

	// Trim both CR and LF to normalize input command string
	cmd = strings.TrimRight(cmd, "\r\n")

	// Handle multiple commands sent in one call (split by newlines)
	cmds := strings.Split(cmd, "\n")
	if len(cmds) > 1 {
		for _, c := range cmds {
			if c = strings.TrimSpace(c); c != "" {
				if err := f.Send(c); err != nil {
					return err
				}
			}
		}
		return nil
	}

	// If we're waiting for input (in preamble or after interactive prompt),
	// echo it and continue with next segment
	if f.waitingForInput {
		// Echo the user input
		f.buffer.WriteString(cmd + "\r\n")

		// Move to next segment
		f.inputIdx++
		if f.inputIdx < len(f.inputSegments) {
			f.buffer.WriteString(f.inputSegments[f.inputIdx])
		}

		// Check if we've processed all segments
		if f.inputIdx >= len(f.inputSegments)-1 {
			f.waitingForInput = false
			// If we need to add a prompt after segments complete
			if f.needsPrompt {
				f.buffer.WriteString(f.sim.device + "#")
				f.needsPrompt = false
			}
		}
		return nil
	}

	// Regular command handling (interactive state)
	// Ignore leading "do " for matching, but remember it for echoing
	lookup := strings.TrimPrefix(cmd, "do ")
	hasDo := len(cmd) != len(lookup)

	// Echo command: if a banner applies, echo the garbled variant
	if b, ok := f.sim.cmd2bCmd[lookup]; ok {
		if hasDo {
			b = "do " + b
		}
		f.buffer.WriteString(b + "\r\n")
	} else {
		f.buffer.WriteString(cmd + "\r\n")
	}

	// Exit immediately after echo if the command is "exit"
	if lookup == "exit" {
		f.done = true
		return nil
	}

	// If there is known output for this command, send it now
	if outText, ok := f.sim.cmd2out[lookup]; ok {
		f.sendText(outText, true)
		if f.waitingForInput {
			return nil
		}
	}

	// Finally, print the device prompt (no line ending in scenario)
	f.buffer.WriteString(f.sim.device + "#")

	return nil
}

// Close closes the fake expecter.
func (f *fakeExpecter) Close() error {
	f.done = true
	return nil
}

// SpawnScenarioFake returns a fake expecter connected to an in-memory
// simulator. The scenario parameter is a file path to the scenario file.
func SpawnScenarioFake(
	device, scenario string,
	timeoutSec int,
) (*fakeExpecter, func(), error) {
	data, err := os.ReadFile(scenario)
	if err != nil {
		return nil, nil, err
	}
	return newFakeExpecter(
		device, string(data), time.Duration(timeoutSec)*time.Second,
	)
}

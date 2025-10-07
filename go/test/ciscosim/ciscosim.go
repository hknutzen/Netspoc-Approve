package ciscosim

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	expect "github.com/tailscale/goexpect"
)

// SpawnScenarioFake creates a fake expecter using goexpect's SpawnFake with batchers
// built from the scenario file. The scenario format uses # to delimit commands and their outputs.
//
// NOTE: This implementation uses goexpect's built-in SpawnFake with Batcher arrays.
// The Batchers define the sequence of BSnd (send), BExp (expect), and BCas (case/switch)
// operations that simulate the router's behavior.
func SpawnScenarioFake(device, scenarioText string, timeoutSec int) (*expect.GExpect, func(), error) {
	batchers, err := parseScenarioToBatchers(device, scenarioText)
	if err != nil {
		return nil, nil, err
	}

	timeout := time.Duration(timeoutSec) * time.Second
	gexp, _, err := expect.SpawnFake(batchers, timeout)
	if err != nil {
		return nil, nil, err
	}

	cleanup := func() {
		gexp.Close()
	}

	return gexp, cleanup, nil
}

// parseScenarioToBatchers parses the scenario text and creates a list of Batchers
// for goexpect's SpawnFake function.
//
// The approach:
// 1. Parse preamble with <!> markers for interactive prompts (login sequence)
// 2. Build command-to-output mapping from scenario
// 3. Create BCas (switch/case) batchers that match commands and respond
// 4. Repeat the BCas pattern to handle multiple commands in sequence
func parseScenarioToBatchers(device, scenarioText string) ([]expect.Batcher, error) {
	// Delimiter: a line starting with '#', optional spaces, capture the command text
	delim := regexp.MustCompile(`(?m)^#[ ]*(.*)[ ]*\n`)

	// Split into preamble, cmd-a, output-a, cmd-b, output-b, ...
	parts := delim.Split(scenarioText, -1)
	matches := delim.FindAllStringSubmatch(scenarioText, -1)

	var batchers []expect.Batcher

	// Handle preamble (login banner, prompts, etc.)
	preamble := ""
	if len(parts) > 0 {
		preamble = parts[0]
		preamble = strings.TrimRight(preamble, "\r\n")
	}

	// Check for EOF marker (connection closes after preamble)
	hasEOF := false
	if preamble != "" && strings.HasSuffix(preamble, "EOF") {
		hasEOF = true
		preamble = strings.TrimSuffix(preamble, "EOF")
		preamble = strings.TrimSpace(preamble)
	}

	// Process preamble with <!> markers for interactive prompts
	// Each <!> means: send text, then wait for user input
	if preamble != "" {
		segments := strings.Split(preamble, "<!>")
		for i, segment := range segments {
			if i > 0 {
				// Before sending this segment, expect user input for the previous prompt
				// Use BExpT (expect with timeout) to wait for user response
				batchers = append(batchers, &expect.BExpT{R: `.+\n`, T: 10})
			}
			// Send this segment
			if segment != "" {
				batchers = append(batchers, &expect.BSnd{S: segment})
			}
		}
	}

	// If EOF marker present, connection closes after preamble
	if hasEOF {
		return batchers, nil
	}

	// Build command-to-output mapping
	cmd2out := make(map[string]string)
	for i := 0; i < len(matches) && i+1 < len(parts); i++ {
		cmd := strings.TrimSpace(matches[i][1])
		out := parts[i+1]
		cmd2out[cmd] = out
	}

	// Handle banner markers (special syntax for variable output)
	reBannerKey := regexp.MustCompile(`^\\\w+/$`)
	reBannerMarker := regexp.MustCompile(`\\\w+/`)
	rePromptNL := regexp.MustCompile(`#\r?\n$`)

	// Collect banner definitions
	banner2out := make(map[string]string)
	for k, v := range cmd2out {
		if reBannerKey.MatchString(k) {
			v = rePromptNL.ReplaceAllString(v, "#")
			banner2out[k] = v
			delete(cmd2out, k)
		}
	}

	// Process banner markers in commands
	cmd2garbled := make(map[string]string)
	cmdKeys := make([]string, 0, len(cmd2out))
	for k := range cmd2out {
		cmdKeys = append(cmdKeys, k)
	}

	for _, orig := range cmdKeys {
		markers := reBannerMarker.FindAllStringIndex(orig, -1)
		if markers == nil {
			continue
		}

		garbled := orig
		stripped := orig
		offsetG := 0
		offsetS := 0

		for _, m := range markers {
			start, end := m[0], m[1]
			marker := orig[start:end]
			bText, ok := banner2out[marker]
			if !ok {
				return nil, fmt.Errorf("unknown banner marker: %s", marker)
			}

			// Garbled version: replace marker with banner text
			gs := start + offsetG
			ge := end + offsetG
			garbled = garbled[:gs] + bText + garbled[ge:]
			offsetG += len(bText) - (end - start)

			// Stripped version: remove marker
			ss := start + offsetS
			se := end + offsetS
			stripped = stripped[:ss] + stripped[se:]
			offsetS -= (end - start)
		}

		out := cmd2out[orig]
		delete(cmd2out, orig)
		cmd2out[stripped] = out
		cmd2garbled[stripped] = garbled
	}

	// Create repeating command handler using BCas (case/switch)
	// We create multiple iterations to handle sequences of commands
	// Each iteration has cases for all possible commands
	maxCommands := 100 // Support up to 100 commands per session

	for iteration := 0; iteration < maxCommands; iteration++ {
		var cases []expect.Caser

		// Build cases for all known commands
		for cmd, output := range cmd2out {
			response := buildCommandResponse(device, cmd, output, cmd2garbled)
			cmdEscaped := regexp.QuoteMeta(cmd)
			// Match command flexibly - with optional "do " prefix
			pattern := fmt.Sprintf(`(?:do\s+)?%s\s*\r?\n`, cmdEscaped)

			cases = append(cases, &expect.BCase{
				R:  pattern,
				S:  response,
				T:  expect.Next(),
				Rt: 0,
			})
		}

		// Special case for "exit" command - terminates the session
		cases = append(cases, &expect.BCase{
			R:  `exit\s*\r?\n`,
			S:  "",
			T:  expect.OK(),
			Rt: 0,
		})

		// Fallback for unknown commands - just echo with prompt
		cases = append(cases, &expect.BCase{
			R:  `(.+)\r?\n`,
			S:  device + "#",
			T:  expect.Next(),
			Rt: 0,
		})

		// Add this iteration's case handler (BCas = Batcher Case Switch)
		batchers = append(batchers, &expect.BCas{C: cases})
	}

	return batchers, nil
}

// buildCommandResponse constructs the full response for a command:
// echo (possibly garbled) + output + prompt
func buildCommandResponse(device, cmd, output string, cmd2garbled map[string]string) string {
	var response strings.Builder

	// Echo the command (use garbled version if available for banner testing)
	if garbled, ok := cmd2garbled[cmd]; ok {
		response.WriteString(garbled)
	} else {
		response.WriteString(cmd)
	}
	response.WriteString("\r\n")

	// Add command output if present
	if output != "" {
		// Handle <!> markers in output (interactive prompts within command output)
		if strings.Contains(output, "<!>") {
			segments := strings.Split(output, "<!>")
			response.WriteString(segments[0])
			// For simplicity, just append remaining segments
			// Full handling would require nested expecter state machine
			for i := 1; i < len(segments); i++ {
				response.WriteString(segments[i])
			}
		} else {
			response.WriteString(output)
		}
	}

	// Add device prompt (unless output already ends with one)
	outputStr := output
	if !strings.HasSuffix(outputStr, device+"#") &&
		!strings.HasSuffix(outputStr, "#\n") &&
		!strings.HasSuffix(outputStr, "#\r\n") &&
		!strings.HasSuffix(outputStr, "#") {
		response.WriteString(device + "#")
	}

	return response.String()
}

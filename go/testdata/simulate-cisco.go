/*
simulate-cisco.go - Simulate Cisco device

SYNOPSIS

	simulate-cisco DEVICE-NAME SCENARIO-FILE

DESCRIPTION

	Reads from STDIN and writes to STDOUT to simulate a Cisco device session.
	A scenario file controls the simulation. It consists of multiple sections:
	  - The first section (before a line starting with '#') is the preamble.
	  - Subsequent sections are pairs of:
	        # command line
	        command output line 1
	        ...

	Behavior:
	  - The preamble (if any) is sent immediately on startup before any input
	    is read. If the preamble ends with the literal "EOF", the string
	    "EOF" is removed, the preamble is printed, and the program exits.
	  - After startup, the program reads single lines from STDIN. If a line
	    exactly matches a command from the scenario, the simulator echoes the
	    command (possibly "garbled" by a banner; see BANNERS), then prints the
	    corresponding command output. If an input line does not match any
	    command, it is echoed unchanged.
	  - After each processed input line, the prompt "DEVICE-NAME#" is sent.
	  - If the input command is exactly "exit" (ignoring a leading "do "),
	    the program exits after echoing the command.
	  - If an input line starts with the prefix "do ", this prefix is ignored
	    for the purpose of command lookup, but preserved when echoing the
	    (possibly garbled) command.
	  - In preamble or command output, any occurrence of the marker sequence
	    "<!>" causes the simulator to read one extra input line from STDIN and
	    discard it (after echoing it back according to the same rules), before
	    continuing to print the remainder of the preamble/output. This models
	    interactive prompts that consume an extra input line.
	  - All output line endings are converted from LF to CRLF.

SCENARIO FILE FORMAT

	The scenario file is a plain text file. Sections are delimited by lines
	beginning with '#'. The text between the start of the file and the first
	such line is the preamble. Each subsequent pair of sections consists of a
	command line (the text after '#') and its associated output text block
	(which may span multiple lines until the next '#' line or EOF).

BANNERS

	Banner messages can be simulated as asynchronous insertions into command
	lines. A banner definition is a section whose command is exactly a marker
	of the form "\MARKER/" (i.e., a backslash, one or more word characters,
	and a trailing slash). The associated output text is the banner text. If
	that banner text ends with "#\n" or "#\r\n", only the trailing newline is
	removed, leaving the trailing '#'.

	To apply a banner, include the same marker ("\MARKER/") inside any normal
	command line in the scenario. During simulation, the command will be echoed
	in a "garbled" form where the marker is replaced by the banner text. The
	lookup for what output to print still uses the original command text with
	the marker removed.

SPECIAL CASES
  - If the scenario file consists of a preamble ending with the literal
    "EOF", the simulator prints the preamble (without "EOF") and exits
    immediately without reading from STDIN.
*/
package main

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// usage prints a short usage message and exits with status 1.
func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s device-name scenario-file\n", os.Args[0])
	os.Exit(1)
}

// sendLine sends a line to STDOUT, replacing LF with CRLF and handling the
// interactive marker "<!>".
// For each occurrence of "<!>", one additional line is read from STDIN and
// recursively passed to sendLine before continuing with the remainder of the
// current line. This simulates interactive prompts that consume an extra input line.
func sendLine(line string, reader *bufio.Reader) {
	// Normalize line endings to CRLF on output
	line = strings.ReplaceAll(line, "\n", "\r\n")

	// Split the line into segments around the interactive marker
	parts := strings.Split(line, "<!>")
	for i, part := range parts {
		// Print the current segment
		fmt.Print(part)
		if i < len(parts)-1 {
			// For each <!> marker, read the next input line from STDIN.
			input, err := reader.ReadString('\n')
			if err != nil {
				// Input closed: stop processing this line.
				return
			}
			// Echo the user input according to the same rules.
			sendLine(input, reader)
		}
	}
}

func main() {
	args := os.Args[1:]

	// Parse device name
	var device string
	if len(args) > 0 {
		device = strings.TrimSpace(args[0])
		args = args[1:]
	} else {
		usage()
	}

	// Parse scenario file path
	var scenarioFile string
	if len(args) > 0 {
		scenarioFile = args[0]
		args = args[1:]
	} else {
		usage()
	}

	// Ensure no extra arguments are provided
	if len(args) > 0 {
		usage()
	}

	// Read the entire scenario file into memory
	data, err := os.ReadFile(scenarioFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Can't open %s: %v\n", scenarioFile, err)
		os.Exit(1)
	}
	scenarioText := string(data)

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
			preamble = strings.TrimSuffix(preamble, "\n")
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
	for _, bCmd := range keys {
		// Find the first banner marker in the command, if any.
		marker := reBannerMarker.FindString(bCmd)
		if marker == "" {
			continue
		}
		// Resolve banner marker to its banner text.
		bText, ok := banner2out[marker]
		if !ok {
			fmt.Fprintf(os.Stderr, "Unknown banner marker: %s\n", marker)
			os.Exit(1)
		}
		out := cmd2out[bCmd]
		delete(cmd2out, bCmd)

		// Original command is the same without the marker (used for lookup).
		cmd := strings.Replace(bCmd, marker, "", 1)
		cmd2out[cmd] = out

		// Garbled command is original with marker replaced by banner text
		// (used for echoing back to the user).
		garbled := strings.Replace(bCmd, marker, bText, 1)
		cmd2bCmd[cmd] = garbled
	}

	// Prepare buffered reader for stdin
	reader := bufio.NewReader(os.Stdin)

	// Send preamble on startup (may contain <!> markers)
	if preamble != "" {
		sendLine(preamble, reader)
	}
	if eof {
		// Early exit after preamble, as requested by scenario
		return
	}

	// Main REPL loop: read a command, echo it (possibly garbled), print
	// associated output, then the device prompt.
	for {
		// Read a single command line from stdin
		input, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		// Trim both CR and LF to normalize input command string
		cmd := strings.TrimRight(input, "\r\n")

		// Ignore leading "do " for matching, but remember it for echoing
		lookup := strings.TrimPrefix(cmd, "do ")
		hasDo := len(cmd) != len(lookup)

		// Echo command: if a banner applies, echo the garbled variant
		if b, ok := cmd2bCmd[lookup]; ok {
			if hasDo {
				b = "do " + b
			}
			sendLine(b+"\n", reader)
		} else {
			sendLine(cmd+"\n", reader)
		}

		// Exit immediately after echo if the command is "exit"
		if lookup == "exit" {
			break
		}

		// If there is known output for this command, send it now
		if out, ok := cmd2out[lookup]; ok {
			sendLine(out, reader)
		}

		// Finally, print the device prompt (no line ending in scenario)
		sendLine(device+"#", reader)
	}
}

package pkg

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/fatih/color"
)

var (
	outMu      sync.Mutex
	outWriter  io.Writer = os.Stdout
	outFile    *os.File
	silent     bool
	jsonOutput bool
)

// ResultEntry stores a verified or candidate origin IP finding.
type ResultEntry struct {
	Domain     string `json:"domain"`
	OriginIP   string `json:"origin_ip"`
	Method     string `json:"method"`
	Confidence string `json:"confidence,omitempty"`
	Details    string `json:"details,omitempty"`
}

// SetSilent configures whether standard informational messages are hidden.
func SetSilent(s bool) {
	outMu.Lock()
	defer outMu.Unlock()
	silent = s
}

// SetNoColor disables ANSI color codes in console output.
func SetNoColor(disabled bool) {
	color.NoColor = disabled
}

// SetJSONOutput enables json formatted log lines.
func SetJSONOutput(enabled bool) {
	outMu.Lock()
	defer outMu.Unlock()
	jsonOutput = enabled
}

// SetOutputFile opens a file path for recording discovered results.
func SetOutputFile(path string) error {
	if path == "" {
		return nil
	}
	outMu.Lock()
	defer outMu.Unlock()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	outFile = f
	return nil
}

// CloseOutput safely flushes and closes any open log file.
func CloseOutput() {
	outMu.Lock()
	defer outMu.Unlock()
	if outFile != nil {
		_ = outFile.Close()
		outFile = nil
	}
}

// PrintInfo prints an informational status message.
func PrintInfo(format string, args ...any) {
	outMu.Lock()
	defer outMu.Unlock()
	if silent {
		return
	}
	symbol := fmt.Sprintf("[%s]", color.BlueString("INF"))
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(outWriter, "%s %s\n", symbol, msg)
}

// PrintSuccess prints an origin match or successful finding.
func PrintSuccess(format string, args ...any) {
	outMu.Lock()
	defer outMu.Unlock()
	symbol := fmt.Sprintf("[%s]", color.GreenString("SUC"))
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(outWriter, "%s %s\n", symbol, msg)
}

// PrintWarning prints a cautionary notice.
func PrintWarning(format string, args ...any) {
	outMu.Lock()
	defer outMu.Unlock()
	if silent {
		return
	}
	symbol := fmt.Sprintf("[%s]", color.YellowString("WRN"))
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(outWriter, "%s %s\n", symbol, msg)
}

// PrintError prints a failure or error message.
func PrintError(format string, args ...any) {
	outMu.Lock()
	defer outMu.Unlock()
	symbol := fmt.Sprintf("[%s]", color.RedString("ERR"))
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(outWriter, "%s %s\n", symbol, msg)
}

// LogFinding records a discovered origin IP to console and optional output file.
func LogFinding(entry ResultEntry) {
	outMu.Lock()
	defer outMu.Unlock()

	if jsonOutput {
		data, err := json.Marshal(entry)
		if err == nil {
			fmt.Fprintln(outWriter, string(data))
			if outFile != nil {
				_, _ = outFile.Write(append(data, '\n'))
			}
		}
		return
	}

	symbol := fmt.Sprintf("[%s]", color.GreenString("SUC"))
	line := fmt.Sprintf("%s %s -> %s (%s)", symbol, entry.Domain, entry.OriginIP, entry.Method)
	if entry.Details != "" {
		line = fmt.Sprintf("%s [%s]", line, entry.Details)
	}
	fmt.Fprintln(outWriter, line)

	if outFile != nil {
		plain := fmt.Sprintf("%s -> %s (%s)", entry.Domain, entry.OriginIP, entry.Method)
		if entry.Details != "" {
			plain = fmt.Sprintf("%s [%s]", plain, entry.Details)
		}
		_, _ = outFile.WriteString(plain + "\n")
	}
}

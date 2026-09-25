package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ANSI SGR codes for colored console output.
const (
	ansiReset   = "\x1b[0m"
	ansiBold    = "\x1b[1m"
	ansiDim     = "\x1b[2m"
	ansiRed     = "\x1b[91m"
	ansiGreen   = "\x1b[92m"
	ansiYellow  = "\x1b[93m"
	ansiCyan    = "\x1b[96m"
	ansiGray    = "\x1b[90m"
	ansiBgGreen = "\x1b[42;30m"
	ansiBgRed   = "\x1b[41;97m"
)

// output routes text to the console (optionally colored) and to a plain-text
// log file simultaneously. Colors are only emitted to the console; the log
// always receives clean, escape-free text.
type output struct {
	logFile *os.File
	color   bool // true when stdout is a console with ANSI enabled
}

var ui *output

// logFilePath returns the path of the results log next to the executable.
func logFilePath() string {
	exe, err := os.Executable()
	if err != nil {
		return "agent-test.log"
	}
	return filepath.Join(filepath.Dir(exe), "agent-test.log")
}

// initOutput sets up console coloring and the plain-text log file. Returns a
// closer for the file.
func initOutput() func() {
	o := &output{}

	// Enable ANSI on the Windows console and remember whether we may colorize.
	// Respect NO_COLOR (https://no-color.org/).
	if stdoutIsConsole() && os.Getenv("NO_COLOR") == "" {
		o.color = enableVirtualTerminal()
	}

	if f, err := os.Create(logFilePath()); err == nil {
		o.logFile = f
	}

	ui = o
	return func() {
		if o.logFile != nil {
			_ = o.logFile.Close()
		}
	}
}

// emit writes a colored variant to the console and a plain variant to the log.
// The two strings should differ only in ANSI codes.
func (o *output) emit(colored, plain string) {
	if o == nil {
		fmt.Print(plain)
		return
	}
	if o.color {
		fmt.Print(colored)
	} else {
		fmt.Print(plain)
	}
	if o.logFile != nil {
		_, _ = o.logFile.WriteString(plain)
	}
}

// line writes a plain line identically to console and log (no color).
func (o *output) line(s string) {
	o.emit(s, s)
}

// colorize wraps s in an ANSI code when coloring is active.
func (o *output) colorize(code, s string) string {
	if o != nil && o.color {
		return code + s + ansiReset
	}
	return s
}

// printf prints an uncolored formatted line to both sinks.
func printf(format string, args ...any) {
	s := fmt.Sprintf(format, args...)
	if ui != nil {
		ui.line(s)
	} else {
		fmt.Print(s)
	}
}

// reporter accumulates pass/fail results and renders them.
type reporter struct {
	passed int
	failed int
	names  []string
}

// status renders a single result row with an aligned, colored status tag.
func (r *reporter) status(tag, tagColor, name, detail string) {
	// Console version: colored tag + name + dim detail.
	plainTag := fmt.Sprintf("[%s]", tag)
	coloredTag := ui.colorize(tagColor, plainTag)

	plainDetail := ""
	coloredDetail := ""
	if detail != "" {
		plainDetail = fmt.Sprintf(" (%s)", detail)
		coloredDetail = " " + ui.colorize(ansiGray, "("+detail+")")
	}

	colored := fmt.Sprintf("  %s %s%s\n", coloredTag, name, coloredDetail)
	plain := fmt.Sprintf("  %-6s %s%s\n", plainTag, name, plainDetail)
	ui.emit(colored, plain)
}

func (r *reporter) pass(name, detail string) {
	r.passed++
	r.names = append(r.names, name)
	r.status("PASS", ansiGreen, name, detail)
}

func (r *reporter) fail(name, detail string) {
	r.failed++
	r.names = append(r.names, name)
	r.status("FAIL", ansiRed, name, detail)
}

func (r *reporter) skip(name, detail string) {
	r.names = append(r.names, name)
	r.status("SKIP", ansiYellow, name, detail)
}

// section prints a section header.
func (r *reporter) section(title string) {
	plain := fmt.Sprintf("\n== %s ==\n", title)
	colored := fmt.Sprintf("\n%s\n", ui.colorize(ansiBold+ansiCyan, "== "+title+" =="))
	ui.emit(colored, plain)
}

// banner prints the utility title banner.
func banner() {
	plain := "\n=== Agent Test Utility ===\n"
	colored := "\n" + ui.colorize(ansiBold+ansiCyan, "=== Agent Test Utility ===") + "\n"
	ui.emit(colored, plain)
}

// summary prints the final tally and returns an exit code (0 if all passed).
func (r *reporter) summary() int {
	total := r.passed + r.failed
	skipped := len(r.names) - total

	ui.emit("\n"+ui.colorize(ansiBold+ansiCyan, "== Summary ==")+"\n", "\n== Summary ==\n")

	// Draw a simple bar of colored blocks: green for pass, red for fail.
	bar := strings.Repeat("#", r.passed)
	failBar := strings.Repeat("#", r.failed)
	coloredBar := ui.colorize(ansiGreen, bar) + ui.colorize(ansiRed, failBar)
	plainBar := bar + failBar
	if plainBar != "" {
		ui.emit("  "+coloredBar+"\n", "  "+plainBar+"\n")
	}

	printf("  passed:  %d\n", r.passed)
	printf("  failed:  %d\n", r.failed)
	if skipped > 0 {
		printf("  skipped: %d\n", skipped)
	}
	printf("  total:   %d\n", total)

	if r.failed == 0 {
		ui.emit(
			"\n  "+ui.colorize(ansiBgGreen+ansiBold, " ALL CHECKS PASSED ")+"\n",
			"\n  ALL CHECKS PASSED\n",
		)
		return 0
	}
	ui.emit(
		"\n  "+ui.colorize(ansiBgRed+ansiBold, " SOME CHECKS FAILED ")+"\n",
		"\n  SOME CHECKS FAILED\n",
	)
	return 1
}

// warnf prints a yellow [WARN] line to the console and a plain one to the log.
func warnf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	ui.emit("  "+ui.colorize(ansiYellow, "[WARN]")+" "+msg+"\n", "  [WARN] "+msg+"\n")
}

// fatalf prints a red [FATAL] line to the console and a plain one to the log.
func fatalf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	ui.emit("  "+ui.colorize(ansiRed, "[FATAL]")+" "+msg+"\n", "  [FATAL] "+msg+"\n")
}

// infof prints a dim informational line to both sinks.
func infof(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	ui.emit(ui.colorize(ansiGray, msg)+"\n", msg+"\n")
}

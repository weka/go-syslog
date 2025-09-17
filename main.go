package main

import (
	"bufio"
	"compress/gzip"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type SyslogMessage struct {
	Timestamp time.Time
	Priority  int
	Facility  int
	Severity  int
	Hostname  string
	Program   string
	PID       string
	Message   string
	Raw       string
}

type Destination struct {
	Path         string
	Template     string
	File         *os.File
	MaxSize      int64
	MaxFiles     int
	CurrentSize  int64
	mu           sync.Mutex
}

type Filter struct {
	Pattern *regexp.Regexp
	Name    string
}

type SyslogServer struct {
	destinations map[string]*Destination
	filters      map[string]*Filter
	mu           sync.RWMutex
	maxSize      int64
	maxFiles     int
}

func NewSyslogServer(maxSize int64, maxFiles int) *SyslogServer {
	server := &SyslogServer{
		destinations: make(map[string]*Destination),
		filters:      make(map[string]*Filter),
		maxSize:      maxSize,
		maxFiles:     maxFiles,
	}

	server.setupDefaultDestinations()
	server.setupDefaultFilters()

	return server
}

func (s *SyslogServer) setupDefaultDestinations() {
	template := "$ISODATE $MSGHDR | $MSG\n"

	destinations := []struct {
		name     string
		path     string
		rotating bool
	}{
		{"d_stdout", "/dev/stdout", false},
		{"d_syslog", "/var/log/syslog", true},
		{"d_error", "/var/log/error", true},
	}

	for _, dest := range destinations {
		if err := s.createDestination(dest.name, dest.path, template, dest.rotating, s.maxSize, s.maxFiles); err != nil {
			log.Printf("Warning: Failed to create destination %s: %v", dest.name, err)
		}
	}
}

func (s *SyslogServer) setupDefaultFilters() {
	s.filters["f_info"] = &Filter{
		Name:    "f_info",
		Pattern: regexp.MustCompile(`(?i).*(NOTICE|WARN(ING)*|ERR(OR)*|CRIT(ICAL)*|ALERT|EMERG(ENCY)*|FATAL|ASSERT):.*`),
	}

	s.filters["f_error"] = &Filter{
		Name:    "f_error",
		Pattern: regexp.MustCompile(`(?i).*(ERR(OR)*|CRIT(ICAL)*|ALERT|EMERG(ENCY)*|FATAL|ASSERT):.*`),
	}
}

func (s *SyslogServer) createDestination(name, path, template string, rotating bool, maxSize int64, maxFiles int) error {
	if path != "/dev/stdout" {
		dir := filepath.Dir(path)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %v", dir, err)
		}
	}

	var file *os.File
	var err error
	var currentSize int64

	if path == "/dev/stdout" {
		file = os.Stdout
		currentSize = 0
	} else {
		file, err = os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return fmt.Errorf("failed to open file %s: %v", path, err)
		}

		if info, err := file.Stat(); err == nil {
			currentSize = info.Size()
		}
	}

	dest := &Destination{
		Path:        path,
		Template:    template,
		File:        file,
		CurrentSize: currentSize,
	}

	if rotating {
		dest.MaxSize = maxSize
		dest.MaxFiles = maxFiles
	}

	s.destinations[name] = dest
	return nil
}

func (s *SyslogServer) writeToDestination(dest *Destination, message string) error {
	if dest.File == os.Stdout {
		_, err := dest.File.WriteString(message)
		return err
	}

	dest.mu.Lock()
	defer dest.mu.Unlock()

	n, err := dest.File.WriteString(message)
	if err != nil {
		return err
	}

	dest.CurrentSize += int64(n)

	if dest.MaxSize > 0 && dest.CurrentSize > dest.MaxSize {
		log.Printf("File %s size %d bytes exceeds limit %d bytes, rotating...", dest.Path, dest.CurrentSize, dest.MaxSize)
		if err := s.rotateLogFile(dest); err != nil {
			return fmt.Errorf("failed to rotate log file %s: %v", dest.Path, err)
		}
	}

	return nil
}

func (s *SyslogServer) rotateLogFile(dest *Destination) error {
	log.Printf("Rotating log file: %s (current size: %d bytes)", dest.Path, dest.CurrentSize)

	// Flush and close the current file
	if err := dest.File.Sync(); err != nil {
		log.Printf("Warning: error syncing file during rotation: %v", err)
	}
	if err := dest.File.Close(); err != nil {
		log.Printf("Warning: error closing file during rotation: %v", err)
	}

	// Create new empty file first
	newFile, err := os.OpenFile(dest.Path+".new", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to create new log file: %v", err)
	}

	// Clean old files
	if err := s.cleanOldLogFiles(dest.Path, dest.MaxFiles); err != nil {
		log.Printf("Warning: error cleaning old log files: %v", err)
	}

	// Rename old file to timestamped name
	timestamp := time.Now().Format("20060102-150405")
	rotatedPath := fmt.Sprintf("%s.%s", dest.Path, timestamp)

	if err := os.Rename(dest.Path, rotatedPath); err != nil {
		newFile.Close()
		os.Remove(dest.Path + ".new")
		return fmt.Errorf("failed to rename log file: %v", err)
	}

	// Move new file to original name
	if err := os.Rename(dest.Path+".new", dest.Path); err != nil {
		newFile.Close()
		return fmt.Errorf("failed to rename new log file: %v", err)
	}

	// Compress old file in background
	go func() {
		if err := s.compressLogFile(rotatedPath); err != nil {
			log.Printf("Warning: failed to compress rotated file %s: %v", rotatedPath, err)
		}
	}()

	// Update destination
	dest.File = newFile
	dest.CurrentSize = 0
	log.Printf("Created new empty log file: %s", dest.Path)

	log.Printf("Log rotation completed for: %s", dest.Path)
	return nil
}

func (s *SyslogServer) compressLogFile(filePath string) error {
	sourceFile, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	gzipPath := filePath + ".gz"
	gzipFile, err := os.Create(gzipPath)
	if err != nil {
		return err
	}
	defer gzipFile.Close()

	gzipWriter := gzip.NewWriter(gzipFile)
	defer gzipWriter.Close()

	_, err = io.Copy(gzipWriter, sourceFile)
	if err != nil {
		return err
	}

	if err := gzipWriter.Close(); err != nil {
		return err
	}

	if err := os.Remove(filePath); err != nil {
		log.Printf("Warning: failed to remove original file after compression: %v", err)
	} else {
		log.Printf("Compressed and removed original file: %s", filePath)
	}

	return nil
}

func (s *SyslogServer) cleanOldLogFiles(basePath string, maxFiles int) error {
	dir := filepath.Dir(basePath)
	base := filepath.Base(basePath)

	files, err := filepath.Glob(filepath.Join(dir, base+".*"))
	if err != nil {
		return err
	}

	var logFiles []string
	for _, file := range files {
		if strings.HasSuffix(file, ".gz") ||
		   (strings.Contains(file, base+".") && !strings.HasSuffix(file, ".gz")) {
			logFiles = append(logFiles, file)
		}
	}

	sort.Strings(logFiles)

	if len(logFiles) >= maxFiles {
		toDelete := logFiles[:len(logFiles)-maxFiles+1]
		for _, file := range toDelete {
			if err := os.Remove(file); err != nil {
				log.Printf("Warning: failed to remove old log file %s: %v", file, err)
			} else {
				log.Printf("Removed old log file: %s", file)
			}
		}
	}

	return nil
}

func (s *SyslogServer) parseSyslogMessage(raw string) *SyslogMessage {
	msg := &SyslogMessage{
		Timestamp: time.Now(),
		Raw:       raw,
		Message:   raw,
		Hostname:  "localhost",
		Program:   "unknown",
	}

	priorityPattern := regexp.MustCompile(`^<(\d+)>(.*)`)
	matches := priorityPattern.FindStringSubmatch(raw)

	if len(matches) >= 3 {
		if priority, err := strconv.Atoi(matches[1]); err == nil {
			msg.Priority = priority
			msg.Facility = priority >> 3
			msg.Severity = priority & 7
		}
		remaining := matches[2]

		timestampPattern := regexp.MustCompile(`^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(.*)`)
		tsMatches := timestampPattern.FindStringSubmatch(remaining)

		if len(tsMatches) >= 3 {
			if ts, err := time.Parse("Jan  2 15:04:05", tsMatches[1]); err == nil {
				msg.Timestamp = ts.AddDate(time.Now().Year(), 0, 0)
			}
			remaining = tsMatches[2]
		}

		hostPattern := regexp.MustCompile(`^(\S+)\s+(.*)`)
		hostMatches := hostPattern.FindStringSubmatch(remaining)

		if len(hostMatches) >= 3 {
			msg.Hostname = hostMatches[1]
			remaining = hostMatches[2]
		}

		progPattern := regexp.MustCompile(`^([^:\[\s]+)(\[(\d+)\])?:\s*(.*)`)
		progMatches := progPattern.FindStringSubmatch(remaining)

		if len(progMatches) >= 5 {
			msg.Program = progMatches[1]
			if progMatches[3] != "" {
				msg.PID = progMatches[3]
			}
			msg.Message = progMatches[4]
		}
	}

	return msg
}

func (s *SyslogServer) formatMessage(msg *SyslogMessage, template string) string {
	result := template

	isodate := msg.Timestamp.Format("2006-01-02T15:04:05-07:00")

	var msghdr string
	if msg.PID != "" {
		msghdr = fmt.Sprintf("%s %s[%s]:", msg.Hostname, msg.Program, msg.PID)
	} else {
		msghdr = fmt.Sprintf("%s %s:", msg.Hostname, msg.Program)
	}

	result = strings.ReplaceAll(result, "$ISODATE", isodate)
	result = strings.ReplaceAll(result, "$MSGHDR", msghdr)
	result = strings.ReplaceAll(result, "$MSG", msg.Message)
	result = strings.ReplaceAll(result, "\\n", "\n")

	return result
}

func (s *SyslogServer) processMessage(msg *SyslogMessage) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	infoFilter := s.filters["f_info"]
	errorFilter := s.filters["f_error"]

	matchesInfo := infoFilter.Pattern.MatchString(msg.Message)
	matchesError := errorFilter.Pattern.MatchString(msg.Message)

	if matchesInfo {
		if dest, exists := s.destinations["d_stdout"]; exists {
			formatted := s.formatMessage(msg, dest.Template)
			if err := s.writeToDestination(dest, formatted); err != nil {
				log.Printf("Error writing to stdout: %v", err)
			}
		}
	}

	if dest, exists := s.destinations["d_syslog"]; exists {
		formatted := s.formatMessage(msg, dest.Template)
		if err := s.writeToDestination(dest, formatted); err != nil {
			log.Printf("Error writing to syslog: %v", err)
		}
	}

	if matchesError {
		if dest, exists := s.destinations["d_error"]; exists {
			formatted := s.formatMessage(msg, dest.Template)
			if err := s.writeToDestination(dest, formatted); err != nil {
				log.Printf("Error writing to error log: %v", err)
			}
		}
	}
}

func (s *SyslogServer) startUnixStream(socketPath string) error {
	if err := os.RemoveAll(socketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove existing socket: %v", err)
	}

	dir := filepath.Dir(socketPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create socket directory: %v", err)
	}

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("failed to listen on unix socket %s: %v", socketPath, err)
	}

	if err := os.Chmod(socketPath, 0666); err != nil {
		log.Printf("Warning: failed to chmod socket: %v", err)
	}

	log.Printf("Syslog server listening on unix-stream socket: %s", socketPath)

	go func() {
		defer listener.Close()
		for {
			conn, err := listener.Accept()
			if err != nil {
				log.Printf("Error accepting unix stream connection: %v", err)
				continue
			}

			go s.handleUnixStreamConnection(conn)
		}
	}()

	return nil
}

func (s *SyslogServer) startUnixDgram(socketPath string) error {
	if err := os.RemoveAll(socketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove existing socket: %v", err)
	}

	dir := filepath.Dir(socketPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create socket directory: %v", err)
	}

	addr, err := net.ResolveUnixAddr("unixgram", socketPath)
	if err != nil {
		return fmt.Errorf("failed to resolve unix dgram address: %v", err)
	}

	conn, err := net.ListenUnixgram("unixgram", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on unix dgram socket %s: %v", socketPath, err)
	}

	if err := os.Chmod(socketPath, 0666); err != nil {
		log.Printf("Warning: failed to chmod socket: %v", err)
	}

	log.Printf("Syslog server listening on unix-dgram socket: %s", socketPath)

	go func() {
		defer conn.Close()
		buffer := make([]byte, 4096)

		for {
			n, _, err := conn.ReadFromUnix(buffer)
			if err != nil {
				log.Printf("Error reading from unix dgram socket: %v", err)
				continue
			}

			message := strings.TrimSpace(string(buffer[:n]))
			if message != "" {
				msg := s.parseSyslogMessage(message)
				s.processMessage(msg)
			}
		}
	}()

	return nil
}

func (s *SyslogServer) handleUnixStreamConnection(conn net.Conn) {
	defer conn.Close()

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		message := strings.TrimSpace(scanner.Text())
		if message != "" {
			msg := s.parseSyslogMessage(message)
			s.processMessage(msg)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("Error reading from unix stream connection: %v", err)
	}
}

func (s *SyslogServer) Start() error {
	streamSocket := "/var/run/go-syslog/go-syslog.sock"
	dgramSocket := "/run/systemd/journal/dev-log"

	if err := s.startUnixStream(streamSocket); err != nil {
		return fmt.Errorf("failed to start unix stream listener: %v", err)
	}

	if err := s.startUnixDgram(dgramSocket); err != nil {
		return fmt.Errorf("failed to start unix dgram listener: %v", err)
	}

	log.Println("Syslog server started successfully with built-in log rotation")

	select {}
}

func (s *SyslogServer) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for name, dest := range s.destinations {
		if dest.File != os.Stdout && dest.File != nil {
			if err := dest.File.Close(); err != nil {
				log.Printf("Error closing destination %s: %v", name, err)
			}
		}
	}

	return nil
}

var version = "dev"

func main() {
	// Define command-line flags
	var (
		showVersion = flag.Bool("version", false, "show version and exit")
		versionShort = flag.Bool("v", false, "show version and exit")
		maxSizeMB = flag.Int("max-size", 1, "maximum log file size in MB before rotation")
		maxFiles = flag.Int("max-files", 10, "maximum number of rotated files to keep")
		showHelp = flag.Bool("help", false, "show help and exit")
		helpShort = flag.Bool("h", false, "show help and exit")
	)

	flag.Parse()

	// Handle version flag
	if *showVersion || *versionShort {
		fmt.Printf("go-syslog %s\n", version)
		os.Exit(0)
	}

	// Handle help flag
	if *showHelp || *helpShort {
		fmt.Printf("go-syslog %s - High-performance syslog server with built-in log rotation\n\n", version)
		fmt.Println("Usage:")
		fmt.Printf("  %s [options]\n\n", os.Args[0])
		fmt.Println("Options:")
		flag.PrintDefaults()
		fmt.Println("\nExamples:")
		fmt.Printf("  %s                          # Use defaults (1MB, 10 files)\n", os.Args[0])
		fmt.Printf("  %s -max-size 5 -max-files 20  # 5MB files, keep 20\n", os.Args[0])
		os.Exit(0)
	}

	// Validate parameters
	if *maxSizeMB <= 0 {
		log.Fatalf("Error: max-size must be greater than 0")
	}
	if *maxFiles <= 0 {
		log.Fatalf("Error: max-files must be greater than 0")
	}

	maxSizeBytes := int64(*maxSizeMB * 1024 * 1024)

	// Set log output to stderr to avoid feedback loop with our own syslog
	log.SetOutput(os.Stderr)
	log.Printf("Starting go-syslog server %s", version)
	log.Printf("Configuration: max-size=%dMB (%d bytes), max-files=%d", *maxSizeMB, maxSizeBytes, *maxFiles)

	server := NewSyslogServer(maxSizeBytes, *maxFiles)
	defer server.Close()

	if err := server.Start(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

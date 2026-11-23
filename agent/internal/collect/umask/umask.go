package umask

import (
	"bufio"
	"errors"
	"io/fs"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/fsread"

	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/emit"
	"github.com/arseniteio/oscompliance-ens-wazuh/catalog/fact"
)

type Config struct {
	Files      []string
	ProfileDir string
}

var DefaultFiles = []string{"/etc/login.defs", "/etc/profile", "/etc/bash.bashrc"}

var octalUmask = regexp.MustCompile(`^[0-7]{1,4}$`)

func Collect(e *emit.Emitter, cfg Config) error {

	paths := append([]string(nil), cfg.Files...)

	if cfg.ProfileDir != "" {
		scripts, _ := filepath.Glob(filepath.Join(cfg.ProfileDir, "*.sh"))
		sort.Strings(scripts)
		paths = append(paths, scripts...)
	}

	snapshot := fact.UmaskSnapshot{Envelope: e.Envelope(fact.UmaskSnapshotFact), Sources: []fact.UmaskSource{}}

	for _, path := range paths {
		if src := readUmask(path); !silent(src) {
			snapshot.Sources = append(snapshot.Sources, src)
		}
	}

	return e.Emit(snapshot)
}

var umaskDecl = regexp.MustCompile(`(?i)(?:^|[\s;&|(])umask\s+([^\s;&|)]+)`)

func readUmask(path string) fact.UmaskSource {

	src := fact.UmaskSource{Path: path, Status: fact.SourceRead, Umasks: []string{}}

	file, err := fsread.Open(path)

	if errors.Is(err, fs.ErrNotExist) {
		return fact.UmaskSource{Path: path, Status: fact.SourceAbsent}
	}

	if err != nil {
		return fact.UmaskSource{Path: path, Status: fact.SourceUnreadable, Error: err.Error()}
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {

		line, _, _ := strings.Cut(scanner.Text(), "#")

		for _, m := range umaskDecl.FindAllStringSubmatch(line, -1) {

			value := m[1]

			if strings.HasPrefix(value, "-") {
				continue
			}

			if !octalUmask.MatchString(value) {
				src.Uninterpretable = append(src.Uninterpretable, value)
				continue
			}

			n, _ := strconv.ParseUint(value, 8, 32)
			src.Umasks = append(src.Umasks, leftPad(strconv.FormatUint(n, 8), 3))
		}
	}

	if err := scanner.Err(); err != nil {
		return fact.UmaskSource{Path: path, Status: fact.SourceUnreadable, Error: err.Error()}
	}

	return src
}

// silent tells a file that was read and declares nothing. The engine has no use
// for it, and on a host with many /etc/profile.d scripts it pushed the line
// past the number of fields the Wazuh JSON decoder accepts.
func silent(src fact.UmaskSource) bool {
	return src.Status == fact.SourceRead && len(src.Umasks) == 0 && len(src.Uninterpretable) == 0
}

func leftPad(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return strings.Repeat("0", n-len(s)) + s
}

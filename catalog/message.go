package catalog

import (
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

type Message struct {
	Code string         `json:"code"`
	Args map[string]any `json:"args,omitempty"`
}

func Says(code string, pairs ...any) Message {

	m := Message{Code: code}
	if len(pairs) == 0 {
		return m
	}

	m.Args = map[string]any{}
	for i := 0; i+1 < len(pairs); i += 2 {
		m.Args[fmt.Sprint(pairs[i])] = pairs[i+1]
	}
	return m
}

func Raw(text string) Message { return Says("raw", "text", text) }

func (m Message) IsZero() bool { return m.Code == "" }

var messages = map[string]map[string]string{}

// {name} renders the argument; {name#singular|plural} renders a count followed by the noun
// phrase that agrees with it ("1 inicio de sesión", "3 inicios de sesión").
var placeholder = regexp.MustCompile(`\{([a-z_]+)(?:#([^|{}]*)\|([^{}]*))?\}`)

func loadMessages() {

	entries, err := files.ReadDir("messages")
	if err != nil {
		panic(err)
	}
	for _, e := range entries {
		raw, err := files.ReadFile(path.Join("messages", e.Name()))
		if err != nil {
			panic(err)
		}
		var texts map[string]string
		if err := json.Unmarshal(raw, &texts); err != nil {
			panic(fmt.Errorf("catalog messages/%s: %w", e.Name(), err))
		}
		messages[strings.TrimSuffix(e.Name(), ".json")] = texts
	}
}

func Messages(lang string) map[string]string { return messages[lang] }

func (m Message) Render(lang string) string {

	text, ok := messages[lang][m.Code]
	if !ok {
		return m.Code
	}

	return strings.TrimSpace(placeholder.ReplaceAllStringFunc(text, func(p string) string {
		parts := placeholder.FindStringSubmatch(p)
		value := renderArg(lang, m.Args[parts[1]])
		if !strings.Contains(p, "#") {
			return value
		}
		if value == "1" {
			return value + " " + parts[2]
		}
		return value + " " + parts[3]
	}))
}

func renderArg(lang string, v any) string {

	switch v := v.(type) {
	case nil:
		return ""
	case string:
		return v
	case Message:
		return v.Render(lang)
	case []Message:
		parts := make([]string, len(v))
		for i, m := range v {
			parts[i] = m.Render(lang)
		}
		return strings.Join(parts, "; ")
	case []string:
		return strings.Join(v, ", ")
	case int:
		return strconv.Itoa(v)
	case int64:
		return strconv.FormatInt(v, 10)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	default:
		return fmt.Sprint(v)
	}
}

func SortMessages(list []Message) {
	slices.SortFunc(list, func(a, b Message) int { return strings.Compare(a.Render("en"), b.Render("en")) })
}

func UniqueMessages(list []Message) []Message {
	seen := map[string]bool{}
	var out []Message
	for _, m := range list {
		k := m.Render("en")
		if !seen[k] {
			seen[k] = true
			out = append(out, m)
		}
	}
	return out
}

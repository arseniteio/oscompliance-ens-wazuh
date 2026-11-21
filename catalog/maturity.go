package catalog

import (
	"encoding/json"
	"sync"
)

type MaturityLevel struct {
	Level   int    `json:"level"`
	Name    string `json:"name"`
	Percent int    `json:"percent"`
}

type MaturityCase struct {
	Percent      int    `json:"percent"`
	Level        string `json:"level"`
	Scale        []int  `json:"scale"`
	ExpectLevel  int    `json:"expectLevel"`
	ExpectStatus string `json:"expectStatus"`
}

type MaturityTable struct {
	Source   string          `json:"source"`
	Levels   []MaturityLevel `json:"levels"`
	Required map[string]int  `json:"required"`
	Cases    []MaturityCase  `json:"cases"`
}

var maturityTable = sync.OnceValue(func() MaturityTable {
	raw, err := files.ReadFile("maturity.json")
	if err != nil {
		panic(err)
	}
	var t MaturityTable
	if err := json.Unmarshal(raw, &t); err != nil {
		panic(err)
	}
	return t
})

func Maturity() MaturityTable { return maturityTable() }

func (t MaturityTable) DefaultScale() []int {
	out := make([]int, 0, len(t.Levels)-1)
	for _, l := range t.Levels[1:] {
		out = append(out, l.Percent)
	}
	return out
}

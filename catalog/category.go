package catalog

import "strings"

// The ENS names the system category BÁSICO, MEDIO or ALTO and the level of each dimension
// BAJO, MEDIO or ALTO. Control and evidence levels in the catalog use the dimension words, so a
// category is compared by its rank; configurations saved before the rename still hold BAJO.
var categoryRanks = map[string]string{
	"BÁSICO": "BAJO",
	"BASICO": "BAJO",
	"BAJO":   "BAJO",
	"MEDIO":  "MEDIO",
	"ALTO":   "ALTO",
}

var categoryLabels = map[string]string{"BAJO": "BÁSICO", "MEDIO": "MEDIO", "ALTO": "ALTO"}

func CategoryRank(category string) string {
	return categoryRanks[strings.ToUpper(strings.TrimSpace(category))]
}

func CategoryLabel(category string) string {
	if label, ok := categoryLabels[CategoryRank(category)]; ok {
		return label
	}
	return category
}

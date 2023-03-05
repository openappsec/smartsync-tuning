package models

// Facet represents the resulting facet on a certain field (key).
type Facet struct {
	Key     string  `json:"key"`
	Buckets Buckets `json:"buckets"`
}

// Facets is a list of Facet
type Facets []Facet

// Bucket collects information on how many documents were found for a certain value of requested Facet
type Bucket struct {
	Value     string `json:"value"`
	DocsCount int    `json:"docsCount"`
}

// Buckets is a list of Bucket
type Buckets []Bucket

// AggregateFacets aggregates the Facets based on max function
func (fts Facets) AggregateFacets() Facets {
	max := func(a, b int) int {
		if a >= b {
			return a
		}

		return b
	}

	// map from facet name to a map of the possible value and its count
	maxFacets := make(map[string]map[string]int)
	for _, f := range fts {
		if mf, ok := maxFacets[f.Key]; !ok {
			maxFacets[f.Key] = make(map[string]int, len(f.Buckets))
			for _, b := range f.Buckets {
				maxFacets[f.Key][b.Value] = b.DocsCount
			}
		} else {
			for _, b := range f.Buckets {
				if currMax, ok := mf[b.Value]; !ok {
					mf[b.Value] = b.DocsCount
				} else {
					mf[b.Value] = max(currMax, b.DocsCount)
				}
			}
		}
	}

	res := make(Facets, 0, len(fts))
	for facetName, facetData := range maxFacets {
		buckets := make(Buckets, 0, len(facetData))
		for val, count := range facetData {
			buckets = append(buckets, Bucket{Value: val, DocsCount: count})
		}

		res = append(res, Facet{Key: facetName, Buckets: buckets})
	}

	return res
}

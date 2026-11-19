package pkg

// ResultCandidate holds an unverified origin IP candidate produced by a discovery technique.
type ResultCandidate struct {
	Domain   string `json:"domain"`
	OriginIP string `json:"origin_ip"`
	Method   string `json:"method"`
	Details  string `json:"details,omitempty"`
}

package fwruleprocessor

type DNSCandidateSource uint8

const (
	DNSCandidateIPCache DNSCandidateSource = iota + 1
	DNSCandidateCIDR
	DNSCandidateNamespace
)

type DNSTier uint8

const (
	DNSTierAdmin DNSTier = iota + 1
	DNSTierNamespace
	DNSTierBaseline
	DNSTierPodDefault
)

type DNSAction uint8

const (
	DNSActionAllow DNSAction = iota + 1
	DNSActionDrop
)

type DNSVerdict uint8

const (
	DNSVerdictNoDecision DNSVerdict = iota
	DNSVerdictAllow
	DNSVerdictDrop
)

type DNSCandidate struct {
	Source   DNSCandidateSource
	Tier     DNSTier
	Priority int
	Action   DNSAction
	Matched  bool
}

func EvaluateDNSCandidates([]DNSCandidate) DNSVerdict {
	return DNSVerdictNoDecision
}

func EncodeDNSPriority(DNSTier, int, DNSAction) uint32 {
	return 0
}

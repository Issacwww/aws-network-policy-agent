package fwruleprocessor

import "sort"

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

func EvaluateDNSCandidates(candidates []DNSCandidate) DNSVerdict {
	valid := make([]DNSCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		if !candidate.Matched {
			continue
		}
		if candidate.Source == DNSCandidateIPCache && candidate.Action != DNSActionAllow {
			continue
		}
		valid = append(valid, candidate)
	}
	sort.SliceStable(valid, func(i, j int) bool {
		if valid[i].Tier != valid[j].Tier {
			return valid[i].Tier < valid[j].Tier
		}
		if valid[i].Priority != valid[j].Priority {
			return valid[i].Priority < valid[j].Priority
		}
		return valid[i].Action == DNSActionDrop && valid[j].Action != DNSActionDrop
	})

	for _, tier := range []DNSTier{DNSTierAdmin, DNSTierNamespace, DNSTierBaseline, DNSTierPodDefault} {
		var tierCandidates []DNSCandidate
		for _, candidate := range valid {
			if candidate.Tier == tier {
				tierCandidates = append(tierCandidates, candidate)
			}
		}
		if len(tierCandidates) == 0 {
			continue
		}
		if tier == DNSTierNamespace {
			for _, candidate := range tierCandidates {
				if candidate.Action == DNSActionAllow {
					return DNSVerdictAllow
				}
			}
			return DNSVerdictDrop
		}
		if tierCandidates[0].Action == DNSActionDrop {
			return DNSVerdictDrop
		}
		return DNSVerdictAllow
	}
	return DNSVerdictNoDecision
}

func EncodeDNSPriority(tier DNSTier, priority int, action DNSAction) uint32 {
	switch tier {
	case DNSTierNamespace:
		priority += 1500
	case DNSTierBaseline:
		priority += BASELINE_TIER_PRIORITY_OFFSET
	case DNSTierPodDefault:
		priority += 3000
	}
	actionValue := 1
	if action == DNSActionDrop {
		actionValue = 0
	}
	return uint32(priority*10 + actionValue)
}

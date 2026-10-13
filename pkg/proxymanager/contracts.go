package proxymanager

import "errors"

var ErrNotImplemented = errors.New("DNS proxy manager is not implemented")

type SyncInput struct {
	FeatureEnabled bool
	PodIdentifier  string
	HostVeth       string
}

type RedirectRequest struct {
	HostVeth                    string
	PreserveOriginalDestination bool
	HookPriority                int
}

type DomainRuleStore interface {
	HasAnyDomainRules(string) bool
}

type RedirectRuleManager interface {
	Add(RedirectRequest) error
}

func SyncPod(SyncInput, DomainRuleStore, RedirectRuleManager) error {
	return ErrNotImplemented
}

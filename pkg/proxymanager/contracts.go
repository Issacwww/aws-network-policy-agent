package proxymanager

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

func SyncPod(input SyncInput, rules DomainRuleStore, redirects RedirectRuleManager) error {
	if !input.FeatureEnabled {
		return nil
	}
	if !rules.HasAnyDomainRules(input.PodIdentifier) {
		return nil
	}
	return redirects.Add(RedirectRequest{
		HostVeth:                    input.HostVeth,
		PreserveOriginalDestination: true,
		HookPriority:                -110,
	})
}

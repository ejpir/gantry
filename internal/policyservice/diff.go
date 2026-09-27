package policyservice

import (
	"fmt"
	"slices"
	"strings"
	"time"

	api "github.com/ejpir/gantry/api/policyservice"
	"github.com/ejpir/gantry/internal/netpol"
	"github.com/ejpir/gantry/internal/policy"
)

// diffDocuments lists what after changes relative to before, rule by rule, in
// a stable order: profile, then network rules, DNS names, and authorization
// rules. A nil before describes a first publication.
func diffDocuments(before *policy.Document, after policy.Document) []api.Change {
	changes := []api.Change{}
	if before == nil {
		for _, name := range sortedProfiles(after) {
			profile := after.Profiles[name]
			changes = append(changes, api.Change{
				Profile: name, Kind: api.ChangeProfile, ID: name, Change: api.ChangeAdded, Effect: api.EffectNeutral,
				Summary: fmt.Sprintf("%d rules · %d network rules · %d DNS names", len(profile.Rules), len(profile.Network.Rules), len(profile.Network.DNS)),
			})
		}
		return changes
	}
	if !before.ExpiresAt.Equal(after.ExpiresAt) {
		effect := api.EffectNeutral
		if after.ExpiresAt.Before(before.ExpiresAt) {
			effect = api.EffectTightens
		}
		changes = append(changes, api.Change{
			Kind: api.ChangeExpiry, Change: api.ChangeChanged, Effect: effect,
			Summary: "Expiry " + day(before.ExpiresAt) + " → " + day(after.ExpiresAt),
			Before:  before.ExpiresAt.UTC().Format(time.RFC3339), After: after.ExpiresAt.UTC().Format(time.RFC3339),
		})
	}
	names := map[string]bool{}
	for name := range before.Profiles {
		names[name] = true
	}
	for name := range after.Profiles {
		names[name] = true
	}
	for _, name := range sortedKeys(names) {
		old, hadOld := before.Profiles[name]
		updated, hasNew := after.Profiles[name]
		switch {
		case !hadOld:
			changes = append(changes, api.Change{Profile: name, Kind: api.ChangeProfile, ID: name, Change: api.ChangeAdded, Effect: api.EffectNeutral,
				Summary: fmt.Sprintf("Profile added · %d rules", len(updated.Rules)+len(updated.Network.Rules))})
		case !hasNew:
			changes = append(changes, api.Change{Profile: name, Kind: api.ChangeProfile, ID: name, Change: api.ChangeRemoved, Effect: api.EffectTightens,
				Summary: "Profile removed"})
		default:
			changes = append(changes, diffNetwork(name, old.Network.Rules, updated.Network.Rules)...)
			changes = append(changes, diffDNS(name, old.Network.DNS, updated.Network.DNS)...)
			changes = append(changes, diffRules(name, old.Rules, updated.Rules)...)
		}
	}
	return changes
}

func diffNetwork(profile string, before, after []netpol.GuardRule) []api.Change {
	return diffByID(profile, api.ChangeNetwork, before, after,
		func(rule netpol.GuardRule) string { return rule.ID },
		func(rule netpol.GuardRule) string { return rule.Effect },
		describeNetwork)
}

func diffRules(profile string, before, after []policy.Rule) []api.Change {
	return diffByID(profile, api.ChangeRule, before, after,
		func(rule policy.Rule) string { return rule.ID },
		func(rule policy.Rule) string { return rule.Effect },
		describeRule)
}

// diffByID compares rules by ID. Adding an allow or removing a deny loosens
// access; the reverse tightens it; an edit that keeps the effect is neutral.
func diffByID[T any](profile, kind string, before, after []T, id func(T) string, effect func(T) string, describe func(T) string) []api.Change {
	old := map[string]T{}
	for _, rule := range before {
		old[id(rule)] = rule
	}
	var changes []api.Change
	seen := map[string]bool{}
	for _, rule := range after {
		key := id(rule)
		seen[key] = true
		previous, existed := old[key]
		switch {
		case !existed:
			changes = append(changes, api.Change{Profile: profile, Kind: kind, ID: key, Change: api.ChangeAdded,
				Effect: grant(effect(rule)), Summary: describe(rule), After: describe(rule)})
		case describe(previous) != describe(rule):
			direction := api.EffectNeutral
			if effect(previous) != effect(rule) {
				direction = grant(effect(rule))
			}
			changes = append(changes, api.Change{Profile: profile, Kind: kind, ID: key, Change: api.ChangeChanged,
				Effect: direction, Summary: describe(rule), Before: describe(previous), After: describe(rule)})
		}
	}
	for _, rule := range before {
		if key := id(rule); !seen[key] {
			changes = append(changes, api.Change{Profile: profile, Kind: kind, ID: key, Change: api.ChangeRemoved,
				Effect: revoke(effect(rule)), Summary: describe(rule), Before: describe(rule)})
		}
	}
	return changes
}

func diffDNS(profile string, before, after []string) []api.Change {
	old := map[string]bool{}
	for _, name := range before {
		old[name] = true
	}
	current := map[string]bool{}
	var changes []api.Change
	for _, name := range after {
		current[name] = true
		if !old[name] {
			changes = append(changes, api.Change{Profile: profile, Kind: api.ChangeDNS, ID: name, Change: api.ChangeAdded,
				Effect: api.EffectLoosens, Summary: name, After: name})
		}
	}
	for _, name := range before {
		if !current[name] {
			changes = append(changes, api.Change{Profile: profile, Kind: api.ChangeDNS, ID: name, Change: api.ChangeRemoved,
				Effect: api.EffectTightens, Summary: name, Before: name})
		}
	}
	return changes
}

func grant(effect string) string {
	if effect == "allow" {
		return api.EffectLoosens
	}
	return api.EffectTightens
}

func revoke(effect string) string {
	if effect == "allow" {
		return api.EffectTightens
	}
	return api.EffectLoosens
}

func describeNetwork(rule netpol.GuardRule) string {
	target := rule.Protocol
	if len(rule.Ports) > 0 {
		ports := make([]string, len(rule.Ports))
		for i, port := range rule.Ports {
			ports[i] = fmt.Sprint(port)
		}
		target += " " + strings.Join(ports, ",")
	}
	return strings.TrimSpace(fmt.Sprintf("%s %s %s", rule.Effect, rule.CIDR, target))
}

func describeRule(rule policy.Rule) string {
	var selector string
	switch rule.Action {
	case policy.MountRead, policy.MountWrite:
		selector = rule.Path
	case policy.MCPConnect:
		selector = rule.Server
	case policy.MCPList, policy.MCPCall:
		selector = rule.Server + " · " + rule.Tool
	case policy.CredentialUse:
		selector = rule.Host
	}
	return fmt.Sprintf("%s %s %s", rule.Effect, rule.Action, selector)
}

func documentCounts(document policy.Document) (rules, dns int) {
	for _, profile := range document.Profiles {
		rules += len(profile.Rules) + len(profile.Network.Rules)
		dns += len(profile.Network.DNS)
	}
	return rules, dns
}

func sortedProfiles(document policy.Document) []string {
	names := make([]string, 0, len(document.Profiles))
	for name := range document.Profiles {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

func sortedKeys(set map[string]bool) []string {
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

func day(value time.Time) string { return value.UTC().Format("2006-01-02") }

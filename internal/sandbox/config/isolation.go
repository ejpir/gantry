package config

// EffectiveProcessIsolation resolves an unset ProcessIsolation to its default.
// An empty value in a persisted configuration predates the field and means
// "auto": try to confine, degrade with a warning where the platform cannot.
func EffectiveProcessIsolation(mode string) string {
	if mode == "" {
		return "auto"
	}
	return mode
}

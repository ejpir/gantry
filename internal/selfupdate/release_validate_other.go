//go:build !darwin

package selfupdate

func validatePlatformSignature(string) error { return nil }

package vsockports

// Windows AF_UNIX endpoints are not represented consistently enough for an
// os.Lstat file-type check. The explicit service allowlist plus the state-tree
// share exclusion remain the security boundary on Windows.
func validateHostSocket(string, uint32) error { return nil }

//go:build windows

package sharefs

func identifyRoot(path string) (Identity, error) {
	backend, err := newWinExportFS(path, 0)
	if err != nil {
		return Identity{}, err
	}
	identity := backend.identity
	if err := backend.Close(); err != nil {
		return Identity{}, err
	}
	return identity, nil
}

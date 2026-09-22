package manifest

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Load reads and compiles one manifest. Relative host paths are resolved from
// the manifest's directory, not the caller's current working directory.
func Load(path string) (Compiled, error) {
	if path == "" {
		return Compiled{}, errors.New("manifest path is required")
	}
	file, err := os.Open(path)
	if err != nil {
		return Compiled{}, err
	}
	defer func() { _ = file.Close() }()
	absolute, err := filepath.Abs(path)
	if err != nil {
		return Compiled{}, err
	}
	return Decode(file, filepath.Dir(absolute))
}

// Decode strictly decodes and compiles one manifest from reader.
func Decode(reader io.Reader, baseDir string) (Compiled, error) {
	raw, err := io.ReadAll(io.LimitReader(reader, maxManifestBytes+1))
	if err != nil {
		return Compiled{}, err
	}
	if len(raw) > maxManifestBytes {
		return Compiled{}, fmt.Errorf("manifest exceeds %d bytes", maxManifestBytes)
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return Compiled{}, errors.New("manifest is empty")
	}
	if err := rejectYAMLExtensions(raw); err != nil {
		return Compiled{}, err
	}
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	decoder.KnownFields(true)
	var document Document
	if err := decoder.Decode(&document); err != nil {
		return Compiled{}, fmt.Errorf("decode manifest: %w", err)
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return Compiled{}, errors.New("manifest must contain exactly one YAML document")
		}
		return Compiled{}, fmt.Errorf("decode trailing manifest document: %w", err)
	}
	return Compile(document, baseDir)
}

func rejectYAMLExtensions(raw []byte) error {
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	for {
		var document yaml.Node
		err := decoder.Decode(&document)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("decode manifest syntax: %w", err)
		}
		if err := walkYAML(&document); err != nil {
			return err
		}
	}
}

func walkYAML(node *yaml.Node) error {
	if node == nil {
		return nil
	}
	if node.Kind == yaml.AliasNode || node.Anchor != "" {
		return fmt.Errorf("manifest line %d: YAML anchors and aliases are not supported", node.Line)
	}
	if node.Value == "<<" {
		return fmt.Errorf("manifest line %d: YAML merge keys are not supported", node.Line)
	}
	if node.Tag != "" && !strings.HasPrefix(node.Tag, "!!") {
		return fmt.Errorf("manifest line %d: custom YAML tag %q is not supported", node.Line, node.Tag)
	}
	for _, child := range node.Content {
		if err := walkYAML(child); err != nil {
			return err
		}
	}
	return nil
}

// Marshal writes a stable two-space-indented YAML representation.
func Marshal(document Document) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := yaml.NewEncoder(&buffer)
	encoder.SetIndent(2)
	if err := encoder.Encode(document); err != nil {
		return nil, err
	}
	if err := encoder.Close(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

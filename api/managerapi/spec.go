// Package managerapi publishes the Gantry manager's versioned OpenAPI contract.
package managerapi

import _ "embed"

// OpenAPI is the OpenAPI 3.1 description served by gantry serve.
//
//go:embed openapi.yaml
var OpenAPI []byte

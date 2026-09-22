package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
)

// actionPayload is the closed wire union. Validation happens before the manager
// selects a sandbox lock; extra payloads must not change the lock's target.
var actionPayload = map[string]string{
	"validate-sandbox-config": "sandboxConfig", "configure-sandbox": "sandboxConfig",
	"validate-rule": "ruleRequest", "add-rule": "ruleRequest", "remove-rule": "rule", "remove-traffic-rule": "traffic",
	"validate-secret": "secret", "add-secret": "secret", "remove-secret": "secretRow",
	"validate-mcp-remote": "mcpRemote", "configure-mcp-remote": "mcpRemote",
	"validate-mcp-filesystem": "mcpFilesystem", "configure-mcp-filesystem": "mcpFilesystem", "remove-mcp-remote": "mcpServer",
	"remove-image": "value", "prune-images": "", "validate-registry": "registry", "store-registry": "registry", "remove-registry": "value",
	"plan-share": "share", "configure-share": "sharePlan", "remove-share": "mount",
	"plan-port": "portRequest", "publish-port": "port", "unpublish-port": "port",
}

func ActionNames() []string {
	names := make([]string, 0, len(actionPayload))
	for name := range actionPayload {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
func ActionPayload(action string) string { return actionPayload[action] }

// ValidateJSON also rejects explicitly null or empty extra payload fields,
// which decoding into optional Go fields alone cannot distinguish from absence.
func (request ActionRequest) ValidateJSON(body []byte) error {
	if err := request.Validate(); err != nil {
		return err
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(body, &envelope); err != nil {
		return errors.New("invalid dashboard action")
	}
	expected := 1
	if ActionPayload(request.Action) != "" {
		expected++
	}
	if len(envelope) != expected {
		return errors.New("dashboard action must contain only its selected payload")
	}
	return nil
}

func (request ActionRequest) Validate() error {
	expected, ok := actionPayload[request.Action]
	if !ok {
		return errors.New("unknown dashboard action")
	}
	value := reflect.ValueOf(request)
	typ := value.Type()
	found := false
	for i := 1; i < value.NumField(); i++ {
		field := value.Field(i)
		if field.IsZero() {
			continue
		}
		tag := typ.Field(i).Tag.Get("json")
		key := tag
		for j, ch := range tag {
			if ch == ',' {
				key = tag[:j]
				break
			}
		}
		if key != expected {
			return errors.New("dashboard action must contain only its selected payload")
		}
		found = true
		if field.Kind() == reflect.Pointer {
			row := field.Elem()
			remote := row.FieldByName("Remote")
			if remote.IsValid() && remote.String() != "" {
				return errors.New("dashboard payload cannot specify another manager")
			}
		}
	}
	if expected != "" && !found {
		return fmt.Errorf("dashboard action requires %s", expected)
	}
	return nil
}

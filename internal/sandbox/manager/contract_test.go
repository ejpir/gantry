package manager

import (
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/ejpir/gantry/api/managerapi"
	"github.com/ejpir/gantry/internal/sandbox/inspection"

	"go.yaml.in/yaml/v3"
)

type contractSchema struct {
	Type       string                    `yaml:"type"`
	Ref        string                    `yaml:"$ref"`
	Properties map[string]contractSchema `yaml:"properties"`
	Required   []string                  `yaml:"required"`
	Enum       []string                  `yaml:"enum"`
	Items      *contractSchema           `yaml:"items"`
}

func TestManagerOpenAPIContract(t *testing.T) {
	var document struct {
		Paths      map[string]map[string]any `yaml:"paths"`
		Components struct {
			Schemas map[string]contractSchema `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(managerapi.OpenAPI, &document); err != nil {
		t.Fatal(err)
	}
	for name, shape := range map[string]any{
		"Sandbox": managerSandbox{}, "BootSettings": inspection.BootSettings{},
		"CreateSandboxRequest": managerCreateRequest{}, "ExecRequest": managerExecRequest{},
		"ExecResult": managerExecResponse{}, "Error": managerErrorResponse{},
		"Operation": managerOperation{}, "Event": managerEvent{},
	} {
		t.Run(name, func(t *testing.T) {
			schema, ok := document.Components.Schemas[name]
			if !ok {
				t.Fatal("schema missing")
			}
			fields := map[string]reflect.Type{}
			typ := reflect.TypeOf(shape)
			for index := 0; index < typ.NumField(); index++ {
				field := typ.Field(index)
				if !field.IsExported() {
					continue
				}
				key := strings.Split(field.Tag.Get("json"), ",")[0]
				if key == "" || key == "-" {
					continue
				}
				fields[key] = field.Type
			}
			for key, typ := range fields {
				property, ok := schema.Properties[key]
				if !ok {
					t.Errorf("JSON field %s is undocumented", key)
					continue
				}
				if property.Ref != "" {
					var found bool
					property, found = document.Components.Schemas[strings.TrimPrefix(property.Ref, "#/components/schemas/")]
					if !found {
						t.Errorf("%s references missing schema", key)
						continue
					}
				}
				for typ.Kind() == reflect.Pointer {
					typ = typ.Elem()
				}
				want := ""
				switch typ.Kind() {
				case reflect.String:
					want = "string"
				case reflect.Bool:
					want = "boolean"
				case reflect.Int, reflect.Int64, reflect.Uint, reflect.Uint64:
					want = "integer"
				case reflect.Slice:
					want = "array"
				case reflect.Struct:
					if typ.PkgPath() == "time" && typ.Name() == "Time" {
						want = "string"
					} else {
						want = "object"
					}
				}
				if want != "" && property.Type != want {
					t.Errorf("%s: Go type %s requires %s, schema has %s", key, typ, want, property.Type)
				}
			}
			for key := range schema.Properties {
				if _, ok := fields[key]; !ok {
					t.Errorf("documented field %s has no JSON field", key)
				}
			}
			for _, key := range schema.Required {
				if _, ok := fields[key]; !ok {
					t.Errorf("required field %s is not implemented", key)
				}
			}
		})
	}
	state := document.Components.Schemas["Sandbox"].Properties["state"].Enum
	if !reflect.DeepEqual(state, []string{string(inspection.Starting), string(inspection.Running), string(inspection.Stopped)}) {
		t.Errorf("sandbox state contract=%v", state)
	}
	file, err := parser.ParseFile(token.NewFileSet(), "manager.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	routes := map[string]bool{}
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || len(call.Args) < 1 {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "HandleFunc" {
			return true
		}
		literal, ok := call.Args[0].(*ast.BasicLit)
		if !ok {
			return true
		}
		pattern, err := strconv.Unquote(literal.Value)
		if err != nil {
			t.Fatal(err)
		}
		method, path, ok := strings.Cut(pattern, " ")
		if !ok {
			return true
		}
		method = strings.ToLower(method)
		routes[method+" "+path] = true
		if _, ok := document.Paths[path][method]; !ok {
			t.Errorf("route %s missing from OpenAPI", pattern)
		}
		return true
	})
	for path, operations := range document.Paths {
		for method := range operations {
			switch method {
			case "get", "post", "delete", "put", "patch":
				if !routes[method+" "+path] {
					t.Errorf("OpenAPI route %s %s is not registered", method, path)
				}
			}
		}
	}
}

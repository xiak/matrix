package installationv1

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/xiak/matrix/api/contractjson"
)

func TestInstallationExamplesPassDomainValidation(t *testing.T) {
	products := decodeInstallationExample[InstalledProductList](t, "examples/installed-products.json")
	if err := ValidateInstalledProductList(products); err != nil {
		t.Fatalf("validate installed products: %v", err)
	}
	readiness := decodeInstallationExample[Readiness](t, "examples/readiness.json")
	if err := ValidateReadiness(readiness); err != nil {
		t.Fatalf("validate readiness: %v", err)
	}
	problem := decodeInstallationExample[Problem](t, "examples/problem.json")
	if err := ValidateProblem(problem); err != nil {
		t.Fatalf("validate problem: %v", err)
	}
}

func TestInstalledProductListRejectsAuthorityAndStateDrift(t *testing.T) {
	valid := validProductList()
	tests := map[string]func(*InstalledProductList){
		"type metadata": func(value *InstalledProductList) {
			value.Kind = "Products"
		},
		"release version": func(value *InstalledProductList) {
			value.ReleaseVersion = "v0.2.0"
		},
		"route": func(value *InstalledProductList) {
			value.Products[0].RouteKey = "devops"
		},
		"unknown product": func(value *InstalledProductList) {
			value.Products[0].ID = ProductID("UNKNOWN")
		},
		"ready reason": func(value *InstalledProductList) {
			value.Products[0].Reason = ReasonObservationStale
		},
		"missing failure reason": func(value *InstalledProductList) {
			value.Products[0].State = ProductUnavailable
		},
		"future observation": func(value *InstalledProductList) {
			value.Products[0].ObservedAt = value.ObservedAt.Add(time.Microsecond)
		},
		"duplicate product": func(value *InstalledProductList) {
			value.Products = append(value.Products, value.Products[0])
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			value := valid
			value.Products = append([]InstalledProduct(nil), valid.Products...)
			mutate(&value)
			if err := ValidateInstalledProductList(value); err == nil {
				t.Fatal("invalid installed-product projection was accepted")
			}
		})
	}
}

func TestInstallationDecoderRejectsForgedAndMalformedFields(t *testing.T) {
	for name, document := range map[string]string{
		"tenant":     `{"tenantId":"organization-forged"}`,
		"credential": `{"credential":"secret"}`,
		"duplicate":  `{"state":"READY","state":"NOT_READY"}`,
		"trailing":   `{"state":"READY"} {}`,
	} {
		t.Run(name, func(t *testing.T) {
			var target maplessInput
			err := Decode(strings.NewReader(document), &target)
			switch name {
			case "tenant", "credential":
				if !errors.Is(err, contractjson.ErrUnknownField) {
					t.Fatalf("forged field error = %v", err)
				}
			case "duplicate":
				if !errors.Is(err, contractjson.ErrDuplicateField) {
					t.Fatalf("duplicate field error = %v", err)
				}
			case "trailing":
				if !errors.Is(err, contractjson.ErrTrailingData) {
					t.Fatalf("trailing data error = %v", err)
				}
			}
		})
	}
}

func TestInstallationWireTypesHaveNoAuthorityOrNativeEscapeHatch(t *testing.T) {
	roots := []reflect.Type{
		reflect.TypeOf(InstalledProduct{}),
		reflect.TypeOf(InstalledProductList{}),
		reflect.TypeOf(Readiness{}),
		reflect.TypeOf(Problem{}),
	}
	seen := map[reflect.Type]bool{}
	for _, root := range roots {
		assertClosedInstallationType(t, root, seen)
	}
}

func TestProductRoutesAreClosed(t *testing.T) {
	for _, id := range AllProductIDs() {
		route, known := ProductRoute(id)
		if !known || route == "" {
			t.Fatalf("product %q has no route", id)
		}
	}
	if _, known := ProductRoute(ProductID("THIRD_PARTY")); known {
		t.Fatal("unregistered product has a route")
	}
}

type maplessInput struct {
	State string `json:"state"`
}

func validProductList() InstalledProductList {
	observed := time.Date(2026, 9, 7, 3, 4, 5, 0, time.UTC)
	return InstalledProductList{
		APIVersion:     APIVersion,
		Kind:           "InstalledProductList",
		ReleaseID:      "matrix-v0.1.0-0123456789ab",
		ReleaseVersion: "v0.1.0",
		Products: []InstalledProduct{{
			ID: ProductApplicationPaaS, Version: "v0.1.0", RouteKey: "paas",
			State: ProductReady, ObservedAt: observed,
		}},
		ObservedAt: observed,
	}
}

func assertClosedInstallationType(t *testing.T, contract reflect.Type, seen map[reflect.Type]bool) {
	t.Helper()
	for contract.Kind() == reflect.Pointer || contract.Kind() == reflect.Slice {
		if contract.Kind() == reflect.Slice && contract.Elem().Kind() == reflect.Uint8 {
			t.Fatalf("installation wire contract contains raw bytes: %s", contract)
		}
		contract = contract.Elem()
	}
	if contract == reflect.TypeOf(time.Time{}) || seen[contract] {
		return
	}
	seen[contract] = true
	switch contract.Kind() {
	case reflect.Map, reflect.Interface:
		t.Fatalf("installation wire contract contains arbitrary %s: %s", contract.Kind(), contract)
	case reflect.Struct:
		for index := range contract.NumField() {
			field := contract.Field(index)
			jsonName := strings.Split(field.Tag.Get("json"), ",")[0]
			normalized := strings.ToLower(jsonName)
			for _, forbidden := range []string{
				"tenant", "organization", "subject", "credential", "secret",
				"native", "payload", "command", "image", "url", "path",
			} {
				if normalized == forbidden || strings.HasSuffix(normalized, forbidden) {
					t.Fatalf("installation wire contract contains forbidden field %s.%s", contract, field.Name)
				}
			}
			assertClosedInstallationType(t, field.Type, seen)
		}
	}
}

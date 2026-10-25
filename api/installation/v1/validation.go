package installationv1

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var (
	versionPattern = regexp.MustCompile(`^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z](?:[0-9A-Za-z.-]{0,62}[0-9A-Za-z])?)?$`)
	releasePattern = regexp.MustCompile(`^matrix-v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z](?:[0-9A-Za-z.-]{0,62}[0-9A-Za-z])?)?-[0-9a-f]{12}$`)
	codePattern    = regexp.MustCompile(`^[a-z][a-z0-9.]{2,127}$`)
)

func ValidateInstalledProduct(value InstalledProduct) error {
	var problems []error
	route, known := ProductRoute(value.ID)
	if !known || value.RouteKey != route {
		problems = append(problems, errors.New("installed product identity or route is invalid"))
	}
	if !versionPattern.MatchString(value.Version) {
		problems = append(problems, errors.New("installed product version is invalid"))
	}
	if !knownProductState(value.State) {
		problems = append(problems, errors.New("installed product state is invalid"))
	}
	switch value.State {
	case ProductReady:
		if value.Reason != "" {
			problems = append(problems, errors.New("ready product cannot contain a reason"))
		}
	case ProductDegraded, ProductUnavailable:
		if !knownProductReason(value.Reason) {
			problems = append(problems, errors.New("non-ready product requires a closed reason"))
		}
	}
	problems = append(problems, validateTimestamp("observedAt", value.ObservedAt))
	return errors.Join(problems...)
}

func ValidateInstalledProductList(value InstalledProductList) error {
	var problems []error
	if value.APIVersion != APIVersion || value.Kind != "InstalledProductList" {
		problems = append(problems, errors.New("installed product list type metadata is invalid"))
	}
	if !releasePattern.MatchString(value.ReleaseID) ||
		!versionPattern.MatchString(value.ReleaseVersion) ||
		!strings.HasPrefix(value.ReleaseID, "matrix-"+value.ReleaseVersion+"-") {
		problems = append(problems, errors.New("installed product release identity is invalid"))
	}
	problems = append(problems, validateTimestamp("observedAt", value.ObservedAt))
	if len(value.Products) == 0 || len(value.Products) > MaxProducts {
		problems = append(problems, errors.New("installed product list size is invalid"))
	}
	previous := ProductID("")
	for _, product := range value.Products {
		problems = append(problems, ValidateInstalledProduct(product))
		if previous >= product.ID {
			problems = append(problems, errors.New("installed products are duplicated or not sorted"))
		}
		if !value.ObservedAt.IsZero() && product.ObservedAt.After(value.ObservedAt) {
			problems = append(problems, errors.New("product observation is newer than its list"))
		}
		previous = product.ID
	}
	return errors.Join(problems...)
}

func ValidateReadiness(value Readiness) error {
	var problems []error
	if value.APIVersion != APIVersion || value.Kind != "Readiness" {
		problems = append(problems, errors.New("installation readiness type metadata is invalid"))
	}
	if value.State != ReadinessReady && value.State != ReadinessNotReady {
		problems = append(problems, errors.New("installation readiness state is invalid"))
	}
	if value.State == ReadinessReady {
		if !releasePattern.MatchString(value.ReleaseID) {
			problems = append(problems, errors.New("ready installation requires its release identity"))
		}
	} else if value.ReleaseID != "" {
		problems = append(problems, errors.New("not-ready installation cannot claim a release"))
	}
	problems = append(problems, validateTimestamp("checkedAt", value.CheckedAt))
	return errors.Join(problems...)
}

func ValidateProblem(value Problem) error {
	var problems []error
	parsed, err := url.Parse(value.Type)
	if err != nil || !parsed.IsAbs() || parsed.Scheme != "https" || parsed.Host != "errors.matrix.xiak.com" {
		problems = append(problems, errors.New("problem type is invalid"))
	}
	if value.Status < 400 || value.Status > 599 || !codePattern.MatchString(value.Code) {
		problems = append(problems, errors.New("problem status or code is invalid"))
	}
	if validateSafeText("title", value.Title, 1, 160) != nil ||
		validateSafeText("requestId", value.RequestID, 1, 128) != nil {
		problems = append(problems, errors.New("problem title or request identity is invalid"))
	}
	if value.Detail != "" {
		problems = append(problems, validateSafeText("detail", value.Detail, 1, 512))
	}
	return errors.Join(problems...)
}

func knownProductState(value ProductState) bool {
	for _, candidate := range AllProductStates() {
		if value == candidate {
			return true
		}
	}
	return false
}

func knownProductReason(value ProductReason) bool {
	for _, candidate := range AllProductReasons() {
		if value == candidate {
			return true
		}
	}
	return false
}

func validateTimestamp(name string, value time.Time) error {
	if value.IsZero() || value.Location() != time.UTC || value != value.Round(0) ||
		value.Nanosecond()%1_000 != 0 {
		return fmt.Errorf("%s is invalid", name)
	}
	return nil
}

func validateSafeText(name, value string, minimum, maximum int) error {
	if !utf8.ValidString(value) || len(value) < minimum || len(value) > maximum ||
		strings.TrimSpace(value) != value {
		return fmt.Errorf("%s is invalid", name)
	}
	for _, character := range value {
		if unicode.IsControl(character) || character == unicode.ReplacementChar {
			return fmt.Errorf("%s is invalid", name)
		}
	}
	return nil
}

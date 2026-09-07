package installationv1

import "time"

type InstalledProduct struct {
	ID         ProductID     `json:"id"`
	Version    string        `json:"version"`
	RouteKey   string        `json:"routeKey"`
	State      ProductState  `json:"state"`
	Reason     ProductReason `json:"reason,omitempty"`
	ObservedAt time.Time     `json:"observedAt"`
}

type InstalledProductList struct {
	APIVersion     string             `json:"apiVersion"`
	Kind           string             `json:"kind"`
	ReleaseID      string             `json:"releaseId"`
	ReleaseVersion string             `json:"releaseVersion"`
	Products       []InstalledProduct `json:"products"`
	ObservedAt     time.Time          `json:"observedAt"`
}

type Readiness struct {
	APIVersion string         `json:"apiVersion"`
	Kind       string         `json:"kind"`
	State      ReadinessState `json:"state"`
	ReleaseID  string         `json:"releaseId,omitempty"`
	CheckedAt  time.Time      `json:"checkedAt"`
}

type Problem struct {
	Type      string `json:"type"`
	Title     string `json:"title"`
	Status    int    `json:"status"`
	Code      string `json:"code"`
	Detail    string `json:"detail,omitempty"`
	RequestID string `json:"requestId"`
}

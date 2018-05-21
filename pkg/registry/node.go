package registry

type URL string

type Node interface {
    GetUrl() URL
    IsAvailable() bool
}

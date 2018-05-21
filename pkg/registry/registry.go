package registry

type Registry interface {
    Node
    RegistryService
}

type RegistryFactory interface {
    Create(url URL) Registry
}


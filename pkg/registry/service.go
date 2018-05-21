package registry

import (
)

type NotifyListener interface {

}

type RegistryService interface {
    Register(url URL)
    UnRegister(url URL)
    Subscribe(url URL, notify NotifyListener)
    UnSubscribe(url URL, notify NotifyListener)
    Lookup(url URL) []URL
}

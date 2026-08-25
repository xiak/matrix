package paasv1

import "fmt"

// AdapterFault transports only a normalized adapter error across the adapter
// boundary. Native errors remain inside the concrete adapter.
type AdapterFault struct {
	Normalized NormalizedAdapterError
}

func (fault AdapterFault) Error() string {
	return fmt.Sprintf("%s: %s", fault.Normalized.Code, fault.Normalized.Message)
}

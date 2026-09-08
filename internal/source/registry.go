package source

import (
	"fmt"
	"sort"
)

type Registry struct {
	adapters map[string]Adapter
}

func NewRegistry(adapters ...Adapter) (*Registry, error) {
	registry := &Registry{adapters: make(map[string]Adapter, len(adapters))}
	for _, adapter := range adapters {
		if adapter == nil {
			return nil, fmt.Errorf("source adapter is nil")
		}
		name := adapter.Name()
		if name == "" {
			return nil, fmt.Errorf("source adapter name is empty")
		}
		if _, exists := registry.adapters[name]; exists {
			return nil, fmt.Errorf("source adapter %q is registered more than once", name)
		}
		registry.adapters[name] = adapter
	}
	return registry, nil
}

func (r *Registry) Get(name string) (Adapter, bool) {
	adapter, ok := r.adapters[name]
	return adapter, ok
}

func (r *Registry) Names() []string {
	names := make([]string, 0, len(r.adapters))
	for name := range r.adapters {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
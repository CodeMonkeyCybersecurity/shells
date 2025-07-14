package plugins

import (
	"fmt"
	"sync"

	"github.com/CodeMonkeyCybersecurity/shells/internal/core"
)

type manager struct {
	scanners map[string]core.Scanner
	mu       sync.RWMutex
}

func NewManager() core.PluginManager {
	return &manager{
		scanners: make(map[string]core.Scanner),
	}
}

func (m *manager) Register(scanner core.Scanner) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	name := scanner.Name()
	if _, exists := m.scanners[name]; exists {
		return fmt.Errorf("scanner %s already registered", name)
	}

	m.scanners[name] = scanner
	return nil
}

func (m *manager) Get(name string) (core.Scanner, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	scanner, exists := m.scanners[name]
	if !exists {
		return nil, fmt.Errorf("scanner %s not found", name)
	}

	return scanner, nil
}

func (m *manager) List() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	names := make([]string, 0, len(m.scanners))
	for name := range m.scanners {
		names = append(names, name)
	}

	return names
}

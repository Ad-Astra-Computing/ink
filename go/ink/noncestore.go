package ink

import (
	"sync"
)

// MemoryNonceStore is an in-process AtomicNonceStore for a single-process
// receiver, the same bounded ring the reference receiver example keeps per
// worker isolate. It is global to the process, which is the stronger of the
// two §3.5 scopes: single use holds across senders with no per-sender key.
//
// Capacity bounds memory against a flood of unique nonces; when the ring is
// full the oldest entry falls off. That eviction is the one way this store can
// forget a nonce inside the five-minute window, so size the capacity above
// the peak number of requests the receiver accepts in five minutes. A
// receiver that runs more than one process needs a shared store instead.
type MemoryNonceStore struct {
	mu       sync.Mutex
	capacity int
	set      map[string]struct{}
	queue    []string
}

// NewMemoryNonceStore returns a store holding at most capacity nonces, with a
// floor of 64.
func NewMemoryNonceStore(capacity int) *MemoryNonceStore {
	if capacity < 64 {
		capacity = 64
	}
	return &MemoryNonceStore{capacity: capacity, set: make(map[string]struct{})}
}

// Has reports whether nonce is recorded.
func (s *MemoryNonceStore) Has(nonce string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.set[nonce]
	return ok, nil
}

// Add records nonce, evicting the oldest entries past capacity. Recording a
// nonce already present is a no-op.
func (s *MemoryNonceStore) Add(nonce string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.add(nonce)
	return nil
}

// AddIfAbsent records nonce under one lock and reports whether it was new.
func (s *MemoryNonceStore) AddIfAbsent(nonce string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.set[nonce]; ok {
		return false, nil
	}
	s.add(nonce)
	return true, nil
}

// Len is the number of nonces currently recorded.
func (s *MemoryNonceStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.set)
}

func (s *MemoryNonceStore) add(nonce string) {
	if _, ok := s.set[nonce]; ok {
		return
	}
	s.set[nonce] = struct{}{}
	s.queue = append(s.queue, nonce)
	for len(s.queue) > s.capacity {
		oldest := s.queue[0]
		s.queue = s.queue[1:]
		delete(s.set, oldest)
	}
}

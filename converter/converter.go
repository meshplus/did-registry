package converter

import (
	"github.com/meshplus/bitxhub-core/boltvm"
	"github.com/meshplus/bitxhub-kit/storage"
)

// StubStorage .
type StubStorage struct {
	boltvm.Stub
}

var _ storage.Storage = (*StubStorage)(nil)

// StubToStorage .
func StubToStorage(stub boltvm.Stub) storage.Storage {
	return &StubStorage{stub}
}

// Get .
func (s *StubStorage) Get(key []byte) []byte {
	exits, data := s.Stub.Get(string(key))
	if !exits {
		return []byte{}
	}
	return data
}

// Has .
func (s *StubStorage) Has(key []byte) bool {
	return s.Stub.Has(string(key))
}

// Close .
func (s *StubStorage) Close() error { return nil }

// Put .
func (s *StubStorage) Put(key, value []byte) {
	s.Stub.Set(string(key), value)
}

// Delete .
func (s *StubStorage) Delete(key []byte) {
	s.Stub.Delete(string(key))
}

/******************************************************************************************/

// NewBatch .
func (s *StubStorage) NewBatch() storage.Batch { return &MockBatch{} }

// Prefix .
func (s *StubStorage) Prefix(prefix []byte) storage.Iterator { return &MockIterator{} }

// Iterator .
func (s *StubStorage) Iterator(start, end []byte) storage.Iterator { return &MockIterator{} }

// MockIterator .
type MockIterator struct{}

func (i *MockIterator) Next() bool           { return false }
func (i *MockIterator) Prev() bool           { return false }
func (i *MockIterator) Seek(key []byte) bool { return false }
func (i *MockIterator) Key() []byte          { return []byte{} }
func (i *MockIterator) Value() []byte        { return []byte{} }

// MockBatch .
type MockBatch struct{}

func (b *MockBatch) Put(key, value []byte) {}
func (b *MockBatch) Delete(key []byte)     {}
func (b *MockBatch) Commit()               {}

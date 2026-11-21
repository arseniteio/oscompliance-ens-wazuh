package source

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
)

func TestManagerInventoryIsReadOncePerPeriod(t *testing.T) {

	var reads atomic.Int32
	s := &Source{}
	s.UseManagerInventory(func(context.Context) (*Inventory, error) {
		reads.Add(1)
		return &Inventory{Packages: map[string]int{"deb": 1}}, nil
	})

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if _, err := s.managerInventory.get(context.Background()); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()

	if reads.Load() != 1 {
		t.Errorf("the manager inventory was read %d times, want 1", reads.Load())
	}
}

package apply

import (
	"testing"
	"time"
)

func TestRunDoesNotBlockOnInheritedPipe(t *testing.T) {
	// Regression: rc scripts hand our output pipe to daemons they spawn;
	// Run must return once the script exits, not when the daemon does.
	done := make(chan error, 1)
	go func() {
		done <- OSSystem{}.Run("sh", "-c", "sleep 30 & exit 0")
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Run blocked on the background child's inherited pipe")
	}
}

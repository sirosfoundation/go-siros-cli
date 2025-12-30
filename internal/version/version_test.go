package version

import (
	"testing"
)

func TestVersion(t *testing.T) {
	// Version is set via ldflags at build time
	// In tests it defaults to "dev"
	if Version == "" {
		t.Error("Version should not be empty")
	}
}

func TestBuildTime(t *testing.T) {
	// BuildTime is set via ldflags at build time
	// In tests it defaults to "unknown"
	if BuildTime == "" {
		t.Error("BuildTime should not be empty")
	}
}

func TestVersionDefaults(t *testing.T) {
	// These test the default values when not set via ldflags
	// During normal test runs, they should be "dev" and "unknown"
	if Version != "dev" {
		t.Logf("Version = %q (expected 'dev' in test environment)", Version)
	}
	if BuildTime != "unknown" {
		t.Logf("BuildTime = %q (expected 'unknown' in test environment)", BuildTime)
	}
}

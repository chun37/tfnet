package hostcfg

import (
	"os"
	"path/filepath"
	"testing"
)

// withEnv temporarily sets env vars for the test; t.Setenv restores them.
func withEnv(t *testing.T, kv map[string]string) {
	t.Helper()
	for k, v := range kv {
		t.Setenv(k, v)
	}
}

func TestLoad_NoFileReturnsZero(t *testing.T) {
	// Point HOME and XDG_CONFIG_HOME at empty dirs and assume /etc/tfnet/config.json
	// either doesn't exist or isn't ours -- we can't unset it. If it does exist,
	// we still expect a non-error and a Config we can use.
	tmp := t.TempDir()
	withEnv(t, map[string]string{
		"HOME":            tmp,
		"XDG_CONFIG_HOME": filepath.Join(tmp, "xdg"),
	})
	cfg, _, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("Load returned nil Config")
	}
}

func TestLoad_XDGTakesPriorityOverHome(t *testing.T) {
	tmp := t.TempDir()
	xdg := filepath.Join(tmp, "xdg")
	home := filepath.Join(tmp, "home")
	if err := os.MkdirAll(filepath.Join(xdg, "tfnet"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".config", "tfnet"), 0o700); err != nil {
		t.Fatal(err)
	}
	xdgFile := filepath.Join(xdg, "tfnet", "config.json")
	homeFile := filepath.Join(home, ".config", "tfnet", "config.json")
	if err := os.WriteFile(xdgFile, []byte(`{"self":"xdg-alice"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(homeFile, []byte(`{"self":"home-bob"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	withEnv(t, map[string]string{
		"HOME":            home,
		"XDG_CONFIG_HOME": xdg,
	})
	cfg, path, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if path != xdgFile {
		t.Errorf("expected loaded path = %s, got %s", xdgFile, path)
	}
	if cfg.Self != "xdg-alice" {
		t.Errorf("expected self=xdg-alice (XDG wins), got %q", cfg.Self)
	}
}

func TestLoad_HomeFallback(t *testing.T) {
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	if err := os.MkdirAll(filepath.Join(home, ".config", "tfnet"), 0o700); err != nil {
		t.Fatal(err)
	}
	homeFile := filepath.Join(home, ".config", "tfnet", "config.json")
	body := `{
        "self": "alice",
        "identity_key": "/etc/tfnet/alice.id.json",
        "repo": "/var/lib/tfnet/repo",
        "branch": "main"
    }`
	if err := os.WriteFile(homeFile, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	withEnv(t, map[string]string{
		"HOME":            home,
		"XDG_CONFIG_HOME": filepath.Join(tmp, "no-xdg"),
	})
	cfg, _, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Self != "alice" || cfg.IdentityKey != "/etc/tfnet/alice.id.json" || cfg.Repo != "/var/lib/tfnet/repo" {
		t.Errorf("unexpected cfg: %+v", cfg)
	}
}

func TestLoad_MalformedReturnsError(t *testing.T) {
	tmp := t.TempDir()
	xdg := filepath.Join(tmp, "xdg")
	if err := os.MkdirAll(filepath.Join(xdg, "tfnet"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(xdg, "tfnet", "config.json"), []byte("{not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	withEnv(t, map[string]string{
		"HOME":            tmp,
		"XDG_CONFIG_HOME": xdg,
	})
	if _, _, err := Load(); err == nil {
		t.Fatal("expected error on malformed config, got nil")
	}
}

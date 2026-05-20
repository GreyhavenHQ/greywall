package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCopyFileTo(t *testing.T) {
	t.Run("copies content and sets executable bit", func(t *testing.T) {
		dir := t.TempDir()
		src := filepath.Join(dir, "src")
		dst := filepath.Join(dir, "dst")

		content := []byte("hello binary")
		if err := os.WriteFile(src, content, 0o600); err != nil {
			t.Fatal(err)
		}

		if err := copyFileTo(src, dst); err != nil {
			t.Fatalf("copyFileTo: %v", err)
		}

		got, err := os.ReadFile(dst) //nolint:gosec // dst is a temp file path from t.TempDir()
		if err != nil {
			t.Fatalf("reading dst: %v", err)
		}
		if string(got) != string(content) {
			t.Errorf("content mismatch: got %q, want %q", got, content)
		}

		info, err := os.Stat(dst)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode()&0o111 == 0 {
			t.Errorf("dst is not executable: mode %v", info.Mode())
		}
	})

	t.Run("overwrites existing dst", func(t *testing.T) {
		dir := t.TempDir()
		src := filepath.Join(dir, "src")
		dst := filepath.Join(dir, "dst")

		if err := os.WriteFile(dst, []byte("old"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(src, []byte("new"), 0o600); err != nil {
			t.Fatal(err)
		}

		if err := copyFileTo(src, dst); err != nil {
			t.Fatalf("copyFileTo: %v", err)
		}

		got, _ := os.ReadFile(dst) //nolint:gosec // dst is a temp file path from t.TempDir()
		if string(got) != "new" {
			t.Errorf("got %q, want %q", got, "new")
		}
	})

	t.Run("returns error for missing src", func(t *testing.T) {
		dir := t.TempDir()
		err := copyFileTo(filepath.Join(dir, "nonexistent"), filepath.Join(dir, "dst"))
		if err == nil {
			t.Fatal("expected error for missing src, got nil")
		}
	})
}

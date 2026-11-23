package main

import (
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

// modernc.org/sqlite runs only with the exact libc and memory versions its own
// go.mod requires; a newer one in our go.mod is picked by MVS and breaks it.
func TestSqliteLibcPinned(t *testing.T) {
	goMod := goList(t, "-m", "-f", "{{.GoMod}}", "modernc.org/sqlite")
	data, err := os.ReadFile(goMod)
	if err != nil {
		t.Fatalf("read sqlite's go.mod: %v", err)
	}
	for _, mod := range []string{"modernc.org/libc", "modernc.org/memory"} {
		m := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(mod) + `\s+(v\S+)`).FindSubmatch(data)
		if m == nil {
			t.Fatalf("%s: not required by sqlite's go.mod %s", mod, goMod)
		}
		want := string(m[1])
		if got := goList(t, "-m", "-f", "{{.Version}}", mod); got != want {
			t.Errorf("%s %s in the build, sqlite requires %s: set it in go.mod", mod, got, want)
		}
	}
}

func goList(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("go", append([]string{"list"}, args...)...).Output()
	if err != nil {
		t.Fatalf("go list %s: %v", strings.Join(args, " "), err)
	}
	return strings.TrimSpace(string(out))
}

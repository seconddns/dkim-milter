package main

import (
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// tagOf is one tag of a DKIM-Signature value, folding removed.
func tagOf(t *testing.T, sig, tag string) string {
	t.Helper()
	flat := strings.NewReplacer("\r\n", "", "\n", "", " ", "", "\t", "").Replace(sig)
	for _, kv := range strings.Split(flat, ";") {
		if k, v, ok := strings.Cut(kv, "="); ok && k == tag {
			return v
		}
	}
	t.Fatalf("no %s= in %q", tag, sig)
	return ""
}

// hList is h= as lower-case names.
func hList(t *testing.T, sig string) []string {
	t.Helper()
	return strings.Split(strings.ToLower(tagOf(t, sig, "h")), ":")
}

func count(list []string, name string) int {
	n := 0
	for _, v := range list {
		if v == name {
			n++
		}
	}
	return n
}

func mustPolicy(t *testing.T, sign, omit, over, cano string) *headerPolicy {
	t.Helper()
	p, err := newHeaderPolicy(sign, omit, over, cano)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// signedMessage signs headers+body under p and returns the signature value
// and the message as sent.
func signedMessage(t *testing.T, p *headerPolicy, headers string) (string, string, string) {
	t.Helper()
	sk := rsaKey(t)
	k := key{domain: "example.org", selector: "s1", signer: sk}
	v, err := signWith(k, p, []byte(headers), []byte(testBody))
	if err != nil {
		t.Fatal(err)
	}
	return v, "DKIM-Signature: " + v + "\r\n" + headers + "\r\n" + testBody, txtRecord(t, sk)
}

// A field of the list the message does not have is not in h=, so a mailing
// list adding List-Id leaves the signature valid.
func TestAbsentFieldsAreNotSigned(t *testing.T) {
	v, msg, rec := signedMessage(t, defaultPolicy(), testHeaders)
	h := hList(t, v)
	for _, n := range []string{"list-id", "reply-to", "cc"} {
		if count(h, n) != 0 {
			t.Errorf("h= has %s, which the message does not: %v", n, h)
		}
	}
	added := strings.Replace(msg, "\r\nFrom:", "\r\nList-Id: <l.example.org>\r\nFrom:", 1)
	if err := verify(t, []byte(added), rec); err != nil {
		t.Errorf("List-Id added after signing breaks the signature: %v", err)
	}
}

// A second From added after signing breaks the signature.
func TestAddedFromBreaksTheSignature(t *testing.T) {
	v, msg, rec := signedMessage(t, defaultPolicy(), testHeaders)
	if count(hList(t, v), "from") != 2 {
		t.Fatalf("h= = %v, want From twice", hList(t, v))
	}
	added := strings.Replace(msg, "\r\nFrom:", "\r\nFrom: mallory@evil.example\r\nFrom:", 1)
	if verify(t, []byte(added), rec) == nil {
		t.Error("a From added after signing still verifies")
	}
}

// A field of oversignHeaders the message did not have is in h= once, and
// adding it after signing breaks the signature.
func TestOversignedAbsentFieldBreaksWhenAdded(t *testing.T) {
	p := mustPolicy(t, defaultSignHeaders, defaultOmitHeaders, "From,Reply-To", defaultCanonicalization)
	v, msg, rec := signedMessage(t, p, testHeaders)
	if count(hList(t, v), "reply-to") != 1 {
		t.Fatalf("h= = %v, want Reply-To once", hList(t, v))
	}
	added := strings.Replace(msg, "\r\nFrom:", "\r\nReply-To: mallory@evil.example\r\nFrom:", 1)
	if verify(t, []byte(added), rec) == nil {
		t.Error("a Reply-To added after signing still verifies")
	}
}

// A field the message has twice is in h= twice.
func TestRepeatedFieldIsSignedEachTime(t *testing.T) {
	hdr := testHeaders + "Cc: a@example.net\r\nCc: b@example.net\r\n"
	v, msg, rec := signedMessage(t, defaultPolicy(), hdr)
	if count(hList(t, v), "cc") != 2 {
		t.Errorf("h= = %v, want Cc twice", hList(t, v))
	}
	if err := verify(t, []byte(msg), rec); err != nil {
		t.Error(err)
	}
}

func TestHeaderListSyntax(t *testing.T) {
	for _, tc := range []struct {
		name, sign, omit string
		in, out          []string
	}{
		{"star adds", "*,+X-Custom", "*", []string{"x-custom", "subject"}, nil},
		{"star removes", "*,-Subject", "*", []string{"to"}, []string{"subject"}},
		{"no star replaces", "Subject", "*", []string{"subject"}, []string{"to", "reply-to"}},
		{"case", "*,+x-CUSTOM,-SUBJECT", "*", []string{"x-custom"}, []string{"subject"}},
		{"omit list replaces", "*", "To", nil, []string{"to"}},
		{"from stays", "*,-From", "From", []string{"from"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := mustPolicy(t, tc.sign, tc.omit, "", defaultCanonicalization)
			for _, n := range tc.in {
				if !p.sign[n] || p.omit[n] {
					t.Errorf("%s is not signed", n)
				}
			}
			for _, n := range tc.out {
				if p.sign[n] && !p.omit[n] {
					t.Errorf("%s is signed", n)
				}
			}
		})
	}
}

// omitHeaders wins over signHeaders: a field in both is not in h= though the
// message has it.
func TestOmitWinsOverSign(t *testing.T) {
	p := mustPolicy(t, "*,+Received", "*", "", defaultCanonicalization)
	v, _, _ := signedMessage(t, p, "Received: from a by b\r\n"+testHeaders)
	if count(hList(t, v), "received") != 0 {
		t.Errorf("h= = %v, has Received", hList(t, v))
	}
	p = mustPolicy(t, "*,+Received", "", "", defaultCanonicalization)
	v, _, _ = signedMessage(t, p, "Received: from a by b\r\n"+testHeaders)
	if count(hList(t, v), "received") != 1 {
		t.Errorf("h= = %v, want Received once with nothing omitted", hList(t, v))
	}
}

// The listener's sessions sign under the configured policy.
func TestMilterServerUsesThePolicy(t *testing.T) {
	p := mustPolicy(t, "Subject", "", "", "simple")
	s, ok := newMilterServer(config{policy: p}, nil).NewMilter().(*session)
	if !ok || s.policy != p {
		t.Fatalf("session policy = %v, want the configured one", s.policy)
	}
}

// From is signed and oversigned whatever the lists say.
func TestFromAlwaysSignedAndGuarded(t *testing.T) {
	p := mustPolicy(t, "*,-From", "*,+From", "", defaultCanonicalization)
	v, msg, rec := signedMessage(t, p, testHeaders)
	if count(hList(t, v), "from") != 2 {
		t.Fatalf("h= = %v, want From twice", hList(t, v))
	}
	added := strings.Replace(msg, "\r\nFrom:", "\r\nFrom: mallory@evil.example\r\nFrom:", 1)
	if verify(t, []byte(added), rec) == nil {
		t.Error("a From added after signing still verifies")
	}
}

// The canonicalization value is c=, every pair verifies, and a lone word is
// the header's with a simple body.
func TestCanonicalization(t *testing.T) {
	for _, tc := range []struct{ value, want string }{
		{"relaxed/simple", "relaxed/simple"},
		{"relaxed/relaxed", "relaxed/relaxed"},
		{"simple/simple", "simple/simple"},
		{"simple/relaxed", "simple/relaxed"},
		{"relaxed", "relaxed/simple"},
		{"Relaxed/Relaxed", "relaxed/relaxed"},
	} {
		t.Run(tc.value, func(t *testing.T) {
			p := mustPolicy(t, defaultSignHeaders, defaultOmitHeaders, defaultOversignHeaders, tc.value)
			v, msg, rec := signedMessage(t, p, testHeaders)
			if got := tagOf(t, v, "c"); got != tc.want {
				t.Errorf("c=%s, want %s", got, tc.want)
			}
			if err := verify(t, []byte(msg), rec); err != nil {
				t.Errorf("does not verify: %v", err)
			}
		})
	}
}

// Each invalid value stops startup, naming the key and the value.
func TestHeaderSettingsRefused(t *testing.T) {
	t.Setenv("DB_DSN", "x")
	t.Setenv("KEY_DECRYPT", "none")
	for _, tc := range []struct{ env, value, sign string }{
		{"OVERSIGN_HEADERS", "Received", "*,+Received"},
		{"SIGN_HEADERS", "", ""},
		{"SIGN_HEADERS", " , ", ""},
		{"SIGN_HEADERS", "-From", ""},
		{"OVERSIGN_HEADERS", "From,X-Unsigned", ""},
		{"OVERSIGN_HEADERS", "Received", ""},
		{"CANONICALIZATION", "", ""},
		{"CANONICALIZATION", "relaxed/nofws", ""},
		{"CANONICALIZATION", "loose", ""},
		{"SIGN_HEADERS", "*,+Bad Name", ""},
	} {
		t.Run(tc.env+"="+tc.value+" "+tc.sign, func(t *testing.T) {
			if tc.sign != "" {
				t.Setenv("SIGN_HEADERS", tc.sign)
			}
			t.Setenv(tc.env, tc.value)
			_, err := loadConfig()
			if err == nil {
				t.Fatal("loaded")
			}
			if !strings.Contains(err.Error(), tc.env) || !strings.Contains(err.Error(), `"`+tc.value+`"`) {
				t.Errorf("error %q does not name %s and %q", err, tc.env, tc.value)
			}
		})
	}
	t.Run("empty oversign is From only", func(t *testing.T) {
		t.Setenv("OVERSIGN_HEADERS", "")
		c, err := loadConfig()
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(c.policy.oversign, []string{"from"}) {
			t.Errorf("oversign = %v", c.policy.oversign)
		}
	})
}

// The settings reach the signer: an environment value, not the default, ends
// up in h= and c=.
func TestHeaderSettingsFromTheEnvironment(t *testing.T) {
	t.Setenv("DB_DSN", "x")
	t.Setenv("KEY_DECRYPT", "none")
	t.Setenv("SIGN_HEADERS", "Subject")
	t.Setenv("OMIT_HEADERS", "")
	t.Setenv("OVERSIGN_HEADERS", "Subject")
	t.Setenv("CANONICALIZATION", "simple/relaxed")
	c, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	v, _, _ := signedMessage(t, c.policy, testHeaders)
	if h := hList(t, v); !slices.Equal(h, []string{"from", "subject", "from", "subject"}) {
		t.Errorf("h= = %v", h)
	}
	if got := tagOf(t, v, "c"); got != "simple/relaxed" {
		t.Errorf("c=%s", got)
	}
}

// The rendered Deployment carries the four values as the variables
// loadConfig reads, and values.yaml has the code's defaults.
func TestChartRendersHeaderSettings(t *testing.T) {
	out, err := exec.Command("helm", "template", "t", "../../helm",
		"--set", "db.dsnSecret.name=s", "--set", "vault.addr=a", "--set", "vault.role=r").CombinedOutput()
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	values := valuesScalars(t, "../../helm/values.yaml")
	settings := []struct{ value, env, def, set string }{
		{"signHeaders", "SIGN_HEADERS", defaultSignHeaders, "Subject"},
		{"omitHeaders", "OMIT_HEADERS", defaultOmitHeaders, "To"},
		{"oversignHeaders", "OVERSIGN_HEADERS", defaultOversignHeaders, ""},
		{"canonicalization", "CANONICALIZATION", defaultCanonicalization, "simple"},
	}
	set := []string{"template", "t", "../../helm", "--set", "db.dsnSecret.name=s", "--set", "vault.addr=a", "--set", "vault.role=r"}
	for _, tc := range settings {
		if got := strings.Trim(values[tc.value], `"`); got != tc.def {
			t.Errorf("%s = %q in values.yaml, %q in the code", tc.value, got, tc.def)
		}
		re := regexp.MustCompile(`- name: ` + tc.env + `\n\s+value: "` + regexp.QuoteMeta(tc.def) + `"`)
		if !re.Match(out) {
			t.Errorf("the rendered Deployment has no %s=%q", tc.env, tc.def)
		}
		set = append(set, "--set-string", tc.value+"="+tc.set)
	}
	out, err = exec.Command("helm", set...).CombinedOutput()
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	for _, tc := range settings {
		re := regexp.MustCompile(`- name: ` + tc.env + `\n\s+value: "` + regexp.QuoteMeta(tc.set) + `"`)
		if !re.Match(out) {
			t.Errorf("with %s=%q set, the rendered Deployment has no %s=%q", tc.value, tc.set, tc.env, tc.set)
		}
	}
}

package main

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"

	"github.com/emersion/go-msgauth/dkim"
)

// The defaults of SIGN_HEADERS, OMIT_HEADERS, OVERSIGN_HEADERS and
// CANONICALIZATION; values.yaml carries the same.
const (
	defaultSignHeaders      = "*,+Message-ID,+MIME-Version,+Content-Type,+Content-Transfer-Encoding"
	defaultOmitHeaders      = "*"
	defaultOversignHeaders  = "From"
	defaultCanonicalization = "relaxed/simple"
)

// standardSign is what "*" means in SIGN_HEADERS: the fields RFC 6376
// section 5.4 says should be signed.
var standardSign = []string{
	"From", "Reply-To", "Subject", "Date", "To", "Cc",
	"Resent-Date", "Resent-From", "Resent-Sender", "Resent-To", "Resent-Cc",
	"In-Reply-To", "References",
	"List-Id", "List-Help", "List-Unsubscribe", "List-Subscribe", "List-Post", "List-Owner", "List-Archive",
}

// standardOmit is what "*" means in OMIT_HEADERS: the fields that should not
// be signed.
var standardOmit = []string{
	"Return-Path", "Received", "Comments", "Keywords", "Bcc", "Resent-Bcc", "DKIM-Signature",
}

// fieldName is a header field name: printable ASCII but space and colon.
var fieldName = regexp.MustCompile(`^[!-9;-~]+$`)

// headerPolicy says which fields of a message go into h=, and how the
// signature is canonicalized.
type headerPolicy struct {
	// sign and omit are lower-case names; omit wins.
	sign, omit map[string]bool
	// oversign are lower-case names, From first.
	oversign   []string
	headerCano dkim.Canonicalization
	bodyCano   dkim.Canonicalization
}

// headerList reads a comma-separated list. With a "*" entry it is a delta to
// standard: +X adds, -X removes; without one it replaces standard. Names are
// lower-cased.
func headerList(key, value string, standard []string) (map[string]bool, []string, error) {
	var entries []string
	star := false
	for _, e := range strings.Split(value, ",") {
		if e = strings.TrimSpace(e); e == "" {
			continue
		}
		if e == "*" {
			star = true
			continue
		}
		entries = append(entries, e)
	}
	set := map[string]bool{}
	var order []string
	add := func(n string) {
		if !set[n] {
			set[n] = true
			order = append(order, n)
		}
	}
	if star {
		for _, n := range standard {
			add(strings.ToLower(n))
		}
	}
	for _, e := range entries {
		remove := strings.HasPrefix(e, "-")
		name := strings.TrimSpace(strings.TrimLeft(e, "+-"))
		if len(e)-len(strings.TrimLeft(e, "+-")) > 1 || !fieldName.MatchString(name) {
			return nil, nil, fmt.Errorf("config: %s %q: %q is not a header field name", key, value, e)
		}
		name = strings.ToLower(name)
		if remove {
			delete(set, name)
			continue
		}
		add(name)
	}
	kept := order[:0]
	for _, n := range order {
		if set[n] {
			kept = append(kept, n)
		}
	}
	return set, kept, nil
}

// parseCanonicalization reads header/body; a lone word is the header's, and
// the body is then simple.
func parseCanonicalization(value string) (dkim.Canonicalization, dkim.Canonicalization, error) {
	word := func(w string) (dkim.Canonicalization, bool) {
		switch strings.ToLower(strings.TrimSpace(w)) {
		case "relaxed":
			return dkim.CanonicalizationRelaxed, true
		case "simple":
			return dkim.CanonicalizationSimple, true
		}
		return "", false
	}
	head, body, two := strings.Cut(value, "/")
	h, ok := word(head)
	if !ok {
		return "", "", fmt.Errorf("config: CANONICALIZATION %q: relaxed or simple, as header/body", value)
	}
	if !two {
		return h, dkim.CanonicalizationSimple, nil
	}
	b, ok := word(body)
	if !ok {
		return "", "", fmt.Errorf("config: CANONICALIZATION %q: relaxed or simple, as header/body", value)
	}
	return h, b, nil
}

// newHeaderPolicy builds the policy from the four values. From is always
// signed and oversigned, whatever the lists say.
func newHeaderPolicy(signV, omitV, oversignV, canoV string) (*headerPolicy, error) {
	sign, _, err := headerList("SIGN_HEADERS", signV, standardSign)
	if err != nil {
		return nil, err
	}
	if len(sign) == 0 {
		return nil, fmt.Errorf("config: SIGN_HEADERS %q is empty: name the fields to sign, or * for the standard list", signV)
	}
	omit, _, err := headerList("OMIT_HEADERS", omitV, standardOmit)
	if err != nil {
		return nil, err
	}
	sign["from"] = true
	delete(omit, "from")
	_, over, err := headerList("OVERSIGN_HEADERS", oversignV, nil)
	if err != nil {
		return nil, err
	}
	p := &headerPolicy{sign: sign, omit: omit, oversign: []string{"from"}}
	for _, n := range over {
		if n == "from" {
			continue
		}
		if !sign[n] || omit[n] {
			return nil, fmt.Errorf("config: OVERSIGN_HEADERS %q: %s is not signed (SIGN_HEADERS, OMIT_HEADERS)", oversignV, n)
		}
		p.oversign = append(p.oversign, n)
	}
	if p.headerCano, p.bodyCano, err = parseCanonicalization(canoV); err != nil {
		return nil, err
	}
	return p, nil
}

// defaultPolicy is the policy of the default values.
func defaultPolicy() *headerPolicy {
	p, err := newHeaderPolicy(defaultSignHeaders, defaultOmitHeaders, defaultOversignHeaders, defaultCanonicalization)
	if err != nil {
		panic(err)
	}
	return p
}

// keys is h= for a header block: each signed field once per time it is
// there, then each oversigned field once more, there or not.
func (p *headerPolicy) keys(headers []byte) []string {
	var out []string
	for _, line := range bytes.Split(headers, []byte("\r\n")) {
		if len(line) == 0 || line[0] == ' ' || line[0] == '\t' {
			continue
		}
		name, _, ok := bytes.Cut(line, []byte(":"))
		if !ok {
			continue
		}
		n := strings.TrimSpace(string(name))
		if l := strings.ToLower(n); p.sign[l] && !p.omit[l] {
			out = append(out, n)
		}
	}
	return append(out, p.oversign...)
}

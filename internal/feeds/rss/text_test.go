package rss

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestPlainText(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, in, want string
	}{
		{"blocks separate words", "<p>One</p><p>two<br/>three</p>", "One two three"},
		{"inline tags join", `Read <a href="https://example.com">the post</a>.`, "Read the post."},
		{"entities", "A &amp; B&nbsp;&#8217;s &quot;C&quot;", "A & B ’s \"C\""},
		{"script and style with their content", "a<script>if (a<b) { x('</p>') }</script>b<STYLE>p{}</STYLE>c", "a b c"},
		{"comment", "a<!-- <p>hidden</p> -->b", "a b"},
		{"literal less-than", "1 < 2 and 3 > 2", "1 < 2 and 3 > 2"},
		{"escaped markup stays text", "&lt;script&gt;alert(1)&lt;/script&gt;", "<script>alert(1)</script>"},
		{"quoted greater-than", `<a title="a>b">x</a>`, "x"},
		{"format characters and whitespace", "\u200bA\n\t B\u00a0 C\u200c ", "A B C"},
		{"unclosed tag", "a <b", "a"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := plainText(tt.in); got != tt.want {
				t.Errorf("plainText(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestPlainTextKeepsAtMostMaxTextRunes(t *testing.T) {
	t.Parallel()
	got := plainText(strings.Repeat("é", maxText+10))
	if n := utf8.RuneCountInString(got); n != maxText {
		t.Errorf("kept %d runes, want %d", n, maxText)
	}
}

func TestParseDate(t *testing.T) {
	t.Parallel()
	want := time.Date(2026, 11, 7, 14, 55, 0, 0, time.UTC)
	for _, in := range []string{
		"Sat, 07 Nov 2026 14:55:00 +0000",
		"Sat, 07 Nov 2026 14:55:00 GMT",
		"Sat, 7 Nov 2026 14:55:00 GMT",
		"Sat, 07 Nov 2026 20:25:00 +0530",
		"Sat, 07 Nov 2026 14:55 +0000",
		"07 Nov 2026 14:55:00 +0000",
		"07 Nov 26 14:55 +0000",
		"07 Nov 26 14:55 UTC",
		"2026-11-07T14:55:00Z",
		"2026-11-07T08:55:00.000-06:00",
		"  Sat, 07 Nov 2026 14:55:00 +0000\n",
	} {
		got, err := parseDate(in)
		if err != nil || !got.Equal(want) || got.Location() != time.UTC {
			t.Errorf("parseDate(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"", "yesterday", "2026-11-07", "Sat Nov 7 14:55:00 2026"} {
		if got, err := parseDate(in); err == nil {
			t.Errorf("parseDate(%q) = %v, want an error", in, got)
		}
	}
}

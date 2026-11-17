package rss

import (
	"html"
	"strings"
	"unicode"
	"unicode/utf8"
)

// maxText is the most runes kept of an item's title or text. A feed gives a
// summary of a few hundred, and what is kept is all the Reader reads (ADR 0025).
const maxText = 4000

// blocks are the elements that separate words, so each of their tags reads as
// a space; any other tag reads as nothing, as <a> or <b> inside a sentence.
var blocks = map[string]bool{
	"address": true, "article": true, "blockquote": true, "br": true, "dd": true, "div": true,
	"dl": true, "dt": true, "figcaption": true, "figure": true, "footer": true, "h1": true,
	"h2": true, "h3": true, "h4": true, "h5": true, "h6": true, "header": true, "hr": true,
	"img": true, "li": true, "ol": true, "p": true, "pre": true, "section": true, "table": true,
	"td": true, "th": true, "tr": true, "ul": true,
}

// plainText is an HTML fragment as a person reads it: tags dropped, script and
// style dropped with their content, entities unescaped, format characters
// such as zero-width spaces dropped and whitespace collapsed, at most maxText
// runes.
func plainText(s string) string {
	var b strings.Builder
	for s != "" {
		i := strings.IndexByte(s, '<')
		if i < 0 {
			b.WriteString(s)
			break
		}
		b.WriteString(s[:i])
		var text string
		text, s = markup(s[i:])
		b.WriteString(text)
	}
	return clip(collapse(html.UnescapeString(b.String())), maxText)
}

// markup reads the markup at the start of s, which starts with '<', and
// returns the text it reads as and what follows it.
func markup(s string) (string, string) {
	if strings.HasPrefix(s, "<!--") {
		return " ", after(s, "-->")
	}
	if len(s) < 2 || !isASCIILetter(s[1]) && s[1] != '/' && s[1] != '!' && s[1] != '?' {
		return "<", s[1:] // a literal '<', as in "a < b"
	}
	name, closing := tagName(s)
	rest := s[tagEnd(s):]
	if !closing && (name == "script" || name == "style") {
		return " ", after(after(rest, "</"+name), ">")
	}
	if blocks[name] {
		return " ", rest
	}
	return "", rest
}

// tagName is the lowercased name of the tag at the start of s, and whether it
// closes an element. A declaration or processing instruction has no name.
func tagName(s string) (string, bool) {
	s = s[1:]
	closing := strings.HasPrefix(s, "/")
	s = strings.TrimPrefix(s, "/")
	n := 0
	for n < len(s) && (isASCIILetter(s[n]) || s[n] >= '0' && s[n] <= '9') {
		n++
	}
	return strings.ToLower(s[:n]), closing
}

// tagEnd is the index just past the '>' that closes the tag at the start of
// s, skipping quoted attribute values, or len(s) when the tag is not closed.
func tagEnd(s string) int {
	var quote byte
	for i := 1; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case (c == '"' || c == '\'') && s[i-1] == '=':
			quote = c
		case c == '>':
			return i + 1
		}
	}
	return len(s)
}

// after is what follows the first sep in s, matched ignoring ASCII case, or
// "" when s has none.
func after(s, sep string) string {
	for i := 0; i+len(sep) <= len(s); i++ {
		if strings.EqualFold(s[i:i+len(sep)], sep) {
			return s[i+len(sep):]
		}
	}
	return ""
}

func isASCIILetter(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// collapse drops format characters and reduces each run of whitespace to one
// space.
func collapse(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, s)
	return strings.Join(strings.Fields(s), " ")
}

func clip(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return strings.TrimSpace(string([]rune(s)[:n]))
}

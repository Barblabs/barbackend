package nvd

import "strings"

// cpe holds the fields of a CPE 2.3 formatted string that matching reads.
type cpe struct {
	vendor, product, version, update string
}

// parseCPE reads a CPE 2.3 formatted string such as
// cpe:2.3:a:tukaani:xz:5.6.1:*:*:*:*:*:*:*. Fields are split on colons that are
// not escaped, and a backslash escape is removed from the value, so Cisco's
// 15.2\(7\)e reads as 15.2(7)e. It reports false for anything else, such as a
// CPE 2.2 URI.
func parseCPE(s string) (cpe, bool) {
	fields := splitCPE(s)
	if len(fields) < 7 || fields[0] != "cpe" || fields[1] != "2.3" {
		return cpe{}, false
	}
	return cpe{vendor: fields[3], product: fields[4], version: fields[5], update: fields[6]}, true
}

func splitCPE(s string) []string {
	var fields []string
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '\\' && i+1 < len(s):
			i++
			b.WriteByte(s[i])
		case s[i] == ':':
			fields = append(fields, b.String())
			b.Reset()
		default:
			b.WriteByte(s[i])
		}
	}
	return append(fields, b.String())
}

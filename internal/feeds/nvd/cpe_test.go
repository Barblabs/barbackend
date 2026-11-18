package nvd

import "testing"

func TestParseCPE(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, in string
		want     cpe
	}{
		{"exact version", "cpe:2.3:a:tukaani:xz:5.6.1:*:*:*:*:*:*:*", cpe{"tukaani", "xz", "5.6.1", "*"}},
		{"version and update", "cpe:2.3:a:apache:log4j:2.0:beta9:*:*:*:*:*:*", cpe{"apache", "log4j", "2.0", "beta9"}},
		{"patch update", "cpe:2.3:a:sudo_project:sudo:1.9.5:patch1:*:*:*:*:*:*", cpe{"sudo_project", "sudo", "1.9.5", "patch1"}},
		{"any version", "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", cpe{"f5", "nginx", "*", "*"}},
		{"no versions", "cpe:2.3:h:cisco:catalyst_9300:-:*:*:*:*:*:*:*", cpe{"cisco", "catalyst_9300", "-", "*"}},
		{"escaped parentheses", `cpe:2.3:o:cisco:ios:15.2\(7\)e:*:*:*:*:*:*:*`, cpe{"cisco", "ios", "15.2(7)e", "*"}},
		{"escaped colon", `cpe:2.3:a:acme:a\:b:1.0:*:*:*:*:*:*:*`, cpe{"acme", "a:b", "1.0", "*"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok := parseCPE(tt.in)
			if !ok || got != tt.want {
				t.Errorf("parseCPE(%q) = %+v, %v; want %+v", tt.in, got, ok, tt.want)
			}
		})
	}
}

func TestParseCPERejectsOtherForms(t *testing.T) {
	t.Parallel()
	for _, in := range []string{
		"",
		"cpe:/a:apache:log4j:2.0",
		"cpe:2.2:a:apache:log4j:2.0:*",
		"cpe:2.3:a:apache:log4j",
	} {
		if got, ok := parseCPE(in); ok {
			t.Errorf("parseCPE(%q) = %+v, want rejected", in, got)
		}
	}
}

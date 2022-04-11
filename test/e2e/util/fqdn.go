package util

import "strings"

// Note: EncodeFQDN and DecodeFQDN functions are copied from
// https://github.com/wmnsk/go-pfcp/blob/master/internal/utils/utils.go
// The package in question is internal and thus can't be used directly
// here.

// We have to update our fork of go-pfcp or use upstream one to use functions below as utils
// EncodeFQDN encodes the given string as the Name Syntax defined
// in RFC 2181, RFC 1035 and RFC 1123.
func EncodeFQDN(fqdn string) []byte {
	b := make([]byte, len(fqdn)+1)

	var offset = 0
	for _, label := range strings.Split(fqdn, ".") {
		l := len(label)
		b[offset] = uint8(l)
		copy(b[offset+1:], label)
		offset += l + 1
	}

	return b
}

// DecodeFQDN decodes the given Name Syntax-encoded []byte as
// a string.
func DecodeFQDN(b []byte) string {
	var (
		fqdn   []string
		offset int
	)

	max := len(b)
	for {
		if offset >= max {
			break
		}
		l := int(b[offset])
		if offset+l+1 > max {
			break
		}
		fqdn = append(fqdn, string(b[offset+1:offset+l+1]))
		offset += l + 1
	}

	return strings.Join(fqdn, ".")
}

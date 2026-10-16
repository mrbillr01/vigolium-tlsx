package ja3

import (
	"crypto/md5"
	"fmt"
	"testing"

	"github.com/zmap/zcrypto/tls"
)

func TestRetiredNPNExtensionFingerprint(t *testing.T) {
	extensions := [][]byte{{0x33, 0x74, 0, 0}}
	client := &tls.ClientHello{Version: 0x0303, CipherSuites: []tls.CipherSuiteID{0x1301}, UnknownExtensions: extensions}
	server := &tls.ServerHello{Version: 0x0303, CipherSuite: 0x1301, UnknownExtensions: extensions}
	if got, want := GetJa3Hash(client), fmt.Sprintf("%x", md5.Sum([]byte("771,4865,13172,,"))); got != want {
		t.Fatalf("JA3 = %s, want %s", got, want)
	}
	if got, want := GetJa3sHash(server), fmt.Sprintf("%x", md5.Sum([]byte("771,4865,13172"))); got != want {
		t.Fatalf("JA3S = %s, want %s", got, want)
	}
}

func TestRetiredExtensionRejectsMalformedLengths(t *testing.T) {
	for _, extension := range [][]byte{nil, {0x33}, {0x33, 0x74}, {0x33, 0x74, 0, 1}} {
		if got := appendUnknownExtensions(nil, [][]byte{extension}); len(got) != 0 {
			t.Fatalf("accepted malformed or different extension %x", extension)
		}
	}
}

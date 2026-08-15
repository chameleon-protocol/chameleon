package tinydoh

import (
	"fmt"
	"net"
	"testing"
	"time"
)

// TestResolver queries a real public resolver, so it needs the internet. It is
// skipped rather than failed when there is none: the test suite runs offline on
// purpose (scripts/test-linux.sh), and a test that cannot tell "the resolver is
// broken" from "there is no network" reports the wrong thing either way.
func TestResolver(t *testing.T) {
	conn, err := net.DialTimeout("tcp", "1.1.1.1:443", 3*time.Second)
	if err != nil {
		t.Skipf("no network access to the test resolver: %v", err)
	}
	_ = conn.Close()

	r := &Resolver{
		URL: "https://1.1.1.1/dns-query",
	}
	ipv4, err := r.LookupA("www.wikipedia.org")
	if err != nil {
		t.Error(err)
	}
	fmt.Println(ipv4)
	ipv6, err := r.LookupAAAA("www.wikipedia.org")
	if err != nil {
		t.Error(err)
	}
	fmt.Println(ipv6)
}

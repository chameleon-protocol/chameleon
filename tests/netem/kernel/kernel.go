// Package kernel drives the platform's real traffic shaper -- tc/netem on
// Linux, dummynet on macOS -- as an optional high-fidelity counterpart to the
// user-space layer in package netem.
//
// It exists to answer the one question the user-space layer cannot: whether a
// result survives contact with the actual kernel datapath, with real syscalls,
// GSO, ECN and socket buffers in play. It is not the default, because it needs
// root and it changes the machine's global network state -- which is also why
// nothing here runs unless HYSTERIA_NETEM_KERNEL is set.
//
// Every profile expressed here must be symmetric: the shaper sits on one
// interface and treats both directions alike.
package kernel

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/apernet/hysteria/tests/v2/netem"
)

// EnableEnv is the environment variable that opts a run into touching the
// machine's network configuration.
const EnableEnv = "HYSTERIA_NETEM_KERNEL"

// Spec is one kernel-level impairment.
type Spec struct {
	// Iface is the interface to shape. Empty means loopback, which is where the
	// test bed's server and client live.
	Iface string
	// Profile must have identical Up and Down links.
	Profile netem.Profile
}

// Availability says whether kernel shaping can be used here, and if not, why
// not -- the reason is meant to be handed to t.Skip so a skipped run explains
// itself.
type Availability struct {
	OK     bool
	Reason string
}

// Check reports whether this process can drive the platform shaper.
func Check() Availability {
	bins := requiredBinaries()
	if len(bins) == 0 {
		return Availability{Reason: "no kernel shaper is wired up for " + runtime.GOOS}
	}
	if os.Getenv(EnableEnv) == "" {
		return Availability{Reason: EnableEnv + " is not set: kernel shaping changes global network state, so it is opt-in"}
	}
	if os.Geteuid() != 0 {
		return Availability{Reason: "kernel shaping needs root"}
	}
	for _, bin := range bins {
		if _, err := exec.LookPath(bin); err != nil {
			return Availability{Reason: bin + " not found in PATH"}
		}
	}
	return Availability{OK: true}
}

func requiredBinaries() []string {
	switch runtime.GOOS {
	case "linux":
		return []string{"tc"}
	case "darwin":
		return []string{"dnctl", "pfctl"}
	default:
		return nil
	}
}

// RequireOrSkip skips the test unless kernel shaping is usable.
func RequireOrSkip(t testing.TB) {
	t.Helper()
	if a := Check(); !a.OK {
		t.Skip("kernel netem unavailable: " + a.Reason)
	}
}

// Apply installs the impairment and registers its removal with t. The teardown
// runs even if the test fails; a leftover qdisc or pf anchor would silently
// impair everything else on the machine.
func Apply(t testing.TB, spec Spec) {
	t.Helper()
	RequireOrSkip(t)
	if spec.Profile.Up != spec.Profile.Down {
		t.Fatalf("kernel shaping is symmetric; profile %s is not", spec.Profile)
	}
	teardown, err := apply(spec)
	if teardown != nil {
		t.Cleanup(func() {
			if err := teardown(); err != nil {
				t.Errorf("removing kernel impairment: %v", err)
			}
		})
	}
	if err != nil {
		t.Fatalf("applying kernel impairment: %v", err)
	}
}

func apply(spec Spec) (func() error, error) {
	iface := spec.Iface
	if iface == "" {
		iface = loopback()
	}
	switch runtime.GOOS {
	case "linux":
		return applyLinux(iface, spec.Profile.Up)
	case "darwin":
		return applyDarwin(spec.Profile.Up)
	default:
		return nil, errors.New("no kernel shaper for " + runtime.GOOS)
	}
}

func loopback() string {
	if runtime.GOOS == "darwin" {
		return "lo0"
	}
	return "lo"
}

// applyLinux installs a netem qdisc at the root of the interface. netem is an
// egress qdisc, and a loopback round trip crosses egress once per direction, so
// a one-way Delay lands as a full RTT of twice that -- the same arithmetic the
// user-space layer uses.
func applyLinux(iface string, link netem.Link) (func() error, error) {
	args := []string{"qdisc", "replace", "dev", iface, "root", "netem"}
	if link.Delay > 0 || link.Jitter > 0 {
		args = append(args, "delay", ms(link.Delay))
		if link.Jitter > 0 {
			args = append(args, ms(link.Jitter), "distribution", "normal")
		}
	}
	switch {
	case link.Blackhole:
		args = append(args, "loss", "100%")
	case link.Loss > 0:
		args = append(args, "loss", fmt.Sprintf("%.4f%%", link.Loss*100))
	}
	if link.Rate > 0 {
		args = append(args, "rate", fmt.Sprintf("%dbit", link.Rate*8))
	}
	if link.Queue > 0 {
		args = append(args, "limit", fmt.Sprint(link.Queue))
	}
	teardown := func() error {
		return run("tc", "qdisc", "del", "dev", iface, "root")
	}
	return teardown, run("tc", args...)
}

// darwinAnchor is the pf anchor the dummynet rules live in, so that teardown
// can flush exactly what was added and nothing else.
const darwinAnchor = "hysteria-netem"

// applyDarwin routes all traffic through a dummynet pipe. Unlike the Linux
// path this shapes every interface, because pf rules are global; the test bed
// only talks to loopback, but anything else running on the machine is affected
// for the duration.
func applyDarwin(link netem.Link) (func() error, error) {
	const pipe = "1"
	config := []string{"pipe", pipe, "config"}
	if link.Delay > 0 {
		config = append(config, "delay", ms(link.Delay))
	}
	switch {
	case link.Blackhole:
		config = append(config, "plr", "1")
	case link.Loss > 0:
		config = append(config, "plr", fmt.Sprintf("%.4f", link.Loss))
	}
	if link.Rate > 0 {
		config = append(config, "bw", fmt.Sprintf("%dbit/s", link.Rate*8))
	}
	if link.Queue > 0 {
		config = append(config, "queue", fmt.Sprint(link.Queue))
	}

	// pf may have been enabled before this run; -E/-X reference count it by
	// token so that teardown gives back exactly what was taken.
	var token string
	teardown := func() error {
		errs := []error{
			run("pfctl", "-a", darwinAnchor, "-F", "all"),
			run("dnctl", "pipe", "delete", pipe),
		}
		if token != "" {
			errs = append(errs, run("pfctl", "-X", token))
		}
		return errors.Join(errs...)
	}
	if err := run("dnctl", config...); err != nil {
		return teardown, err
	}
	rules := fmt.Sprintf("dummynet in quick proto udp from any to any pipe %s\n"+
		"dummynet out quick proto udp from any to any pipe %s\n", pipe, pipe)
	if err := runStdin(rules, "pfctl", "-a", darwinAnchor, "-f", "-"); err != nil {
		return teardown, err
	}
	out, err := output("pfctl", "-E")
	if err != nil {
		return teardown, err
	}
	token = parseToken(out)
	return teardown, nil
}

// parseToken pulls the reference token out of "pfctl -E" output, whose only
// machine-readable form is a "Token : 12345678" line.
func parseToken(out string) string {
	for _, line := range strings.Split(out, "\n") {
		_, rest, ok := strings.Cut(line, "Token :")
		if ok {
			return strings.TrimSpace(rest)
		}
	}
	return ""
}

// ms renders a duration the way tc and dnctl want it.
func ms(d time.Duration) string {
	return fmt.Sprintf("%dms", d.Milliseconds())
}

func run(name string, args ...string) error {
	return runStdin("", name, args...)
}

func runStdin(stdin, name string, args ...string) error {
	_, err := outputStdin(stdin, name, args...)
	return err
}

func output(name string, args ...string) (string, error) {
	return outputStdin("", name, args...)
}

func outputStdin(stdin, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

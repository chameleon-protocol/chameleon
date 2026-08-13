//go:build !race

package e2e

// raceDetector reports whether this binary was built with -race.
//
// The detector costs roughly an order of magnitude of throughput through the
// user-space impairment layer, which is invisible to any assertion phrased as a
// ratio between two flows but decides the outcome of one phrased as an absolute
// rate. Tests that name a rate the bed has to supply consult this.
const raceDetector = false

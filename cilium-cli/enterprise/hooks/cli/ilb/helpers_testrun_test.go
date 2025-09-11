package ilb

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_testsToExecute(t *testing.T) {
	// Override global var for testing
	Tests = []func(t T){
		TestRequestedVIP,
		TestSharedVIP,
		TestBGPHealthCheck,
		TestBGPHealthCheckSubset,
		TestHTTPAndT2HealthChecks,
		TestHTTP2,
		TestHTTPPath,
		TestHTTPRoutes,
	}

	testCases := []struct {
		flagRun       []string
		expectedTests []string
	}{
		{
			flagRun: []string{},
			expectedTests: []string{
				"TestRequestedVIP",
				"TestSharedVIP",
				"TestBGPHealthCheck",
				"TestBGPHealthCheckSubset",
				"TestHTTPAndT2HealthChecks",
				"TestHTTP2",
				"TestHTTPPath",
				"TestHTTPRoutes",
			},
		},
		{
			flagRun: []string{
				"TestRequestedVIP",
				"!TestSharedVIP",
				"!^TestBGPHealthCheck",
				"!^TestBGPHealthCheckSubset$",
				"^TestHTTP",
			},
			expectedTests: []string{
				"TestRequestedVIP",
				"TestHTTPAndT2HealthChecks",
				"TestHTTP2",
				"TestHTTPPath",
				"TestHTTPRoutes",
			},
		},
	}

	for _, tt := range testCases {
		FlagRun = tt.flagRun
		// function to test
		actualTests, err := NewLBTestRun(t.Context(), "cilium").testsToExecute(t.Context())

		require.NoError(t, err)
		require.Len(t, actualTests, len(tt.expectedTests))
		for i := range actualTests {
			require.Equal(t, tt.expectedTests[i], actualTests[i].Name())
		}
	}
}

func Test_runAndSkipRegexps(t *testing.T) {
	testCases := []struct {
		flagRun      []string
		runExpected  []*regexp.Regexp
		skipExpected []*regexp.Regexp
	}{
		{
			flagRun:      []string{},
			runExpected:  []*regexp.Regexp{},
			skipExpected: []*regexp.Regexp{},
		},
		{
			flagRun: []string{"!SkipTest1", "RunTest2", "!^SkipTest3$", "^RunTest4$"},
			runExpected: []*regexp.Regexp{
				regexp.MustCompile("RunTest2"),
				regexp.MustCompile("^RunTest4$"),
			},
			skipExpected: []*regexp.Regexp{
				regexp.MustCompile("SkipTest1"),
				regexp.MustCompile("^SkipTest3$"),
			},
		},
	}

	for _, tt := range testCases {
		FlagRun = tt.flagRun
		// function to test
		runActual, skipActual, err := runAndSkipRegexps()

		require.NoError(t, err)
		require.Equal(t, tt.runExpected, runActual)
		require.Equal(t, tt.skipExpected, skipActual)
	}
}

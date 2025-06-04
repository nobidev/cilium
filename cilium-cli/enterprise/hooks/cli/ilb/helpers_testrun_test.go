package ilb

import (
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_testsToExecute(t *testing.T) {
	testCases := []struct {
		flagRun []string
	}{
		{
			flagRun: []string{},
		},
		{
			flagRun: []string{
				"TestRequestedVIP",
				"!TestLabelBasedBackend",
				"!^TestTCPProxyT1Only$",
				"!TestTCPProxyAuto$",
				"!^TestUDPProxyT1Only",
				"!TestUDPProxyAuto$",
				"^TestTCPProxyT1T2$",
			},
		},
	}

	for _, tt := range testCases {
		FlagRun = tt.flagRun
		// function to test
		actual, err := NewLBTestRun(t.Context()).testsToExecute(t.Context())

		require.NoError(t, err)

		// if no flags provided we should have all the tests
		if len(tt.flagRun) == 0 {
			require.Len(t, actual, len(Tests))
			continue
		}

		for _, expectedRegexp := range tt.flagRun {
			expected := removeRegexpChars(expectedRegexp)

			// check that test has been filetered out
			if strings.HasPrefix(expectedRegexp, "!") {
				for _, actualTest := range actual {
					require.NotEqual(t, expected, actualTest.Name())
				}
				continue
			}

			// check that test presents
			found := false
			for _, actualTest := range actual {
				if actualTest.Name() == expected {
					found = true
					break
				}
			}
			require.True(t, found)
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

func removeRegexpChars(s string) string {
	return strings.TrimPrefix(strings.TrimPrefix(strings.TrimSuffix(s, "$"), "^"), "!")
}

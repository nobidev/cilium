package status

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCountIPs(t *testing.T) {
	testCases := []struct {
		ok             int
		total          int
		expectedStatus string
	}{
		{
			ok:             1,
			total:          1,
			expectedStatus: "OK",
		},
		{
			ok:             1,
			total:          2,
			expectedStatus: "DEG",
		},
		{
			ok:             0,
			total:          0,
			expectedStatus: "DEG",
		},
	}

	lb := &LoadbalancerClient{}
	for _, tc := range testCases {
		require.Equal(t, tc.expectedStatus, lb.statusText(tc.ok, tc.total))
	}
}

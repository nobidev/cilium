// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package export

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"golang.org/x/time/rate"

	"github.com/cilium/cilium/pkg/time"
)

func TestNewRateLimiter(t *testing.T) {
	log := logrus.New()
	log.SetOutput(io.Discard)

	_, err := NewRateLimiter(0, time.Minute, "", log)
	assert.NoError(t, err)

	_, err = NewRateLimiter(-1, time.Minute, "", log)
	assert.Errorf(t, err, "numEvents cannot be negative")
}

func Test_getLimit(t *testing.T) {
	assert.Equal(t, rate.Limit(0), getLimit(0, time.Minute))
	assert.Equal(t, rate.Limit(0), getLimit(0, 0))
	assert.Equal(t, rate.Limit(1), getLimit(60, time.Minute))
	assert.Equal(t, rate.Limit(10.0/60), getLimit(10, time.Minute))
	// 1/ms => 1000/second
	assert.Equal(t, rate.Limit(1000), getLimit(1, time.Millisecond))
	// 3600/hour => 1/second
	assert.Equal(t, rate.Limit(1), getLimit(60*60, time.Hour))

	// interval<=0 => infinite rate limit (allow all events)
	assert.Equal(t, rate.Inf, getLimit(1, 0))
	assert.Equal(t, rate.Inf, getLimit(1, -1))
}

func TestEnforce(t *testing.T) {
	log := logrus.New()
	log.SetOutput(io.Discard)

	interval := 1 * time.Second
	numEvents := 2
	numCalls := 10
	want := numCalls - numEvents

	rl, err := NewRateLimiter(numEvents, interval, "node-name", log)
	assert.NoError(t, err)

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)

	got := 0
	for i := range numCalls {
		rl.curTime = func() time.Time { return mustParseTime(t, fmt.Sprintf("2001-01-01T01:01:%02dZ", i)) }
		if rl.Enforce(enc) {
			got += 1
		}
	}

	assert.Equal(t, want, got)

	wantJSON := []string{
		`{"rate_limit_info":{"number_of_dropped_events":1},"node_name":"node-name","time":"2001-01-01T01:01:02Z"}`,
		`{"rate_limit_info":{"number_of_dropped_events":2},"node_name":"node-name","time":"2001-01-01T01:01:04Z"}`,
		`{"rate_limit_info":{"number_of_dropped_events":2},"node_name":"node-name","time":"2001-01-01T01:01:06Z"}`,
		`{"rate_limit_info":{"number_of_dropped_events":2},"node_name":"node-name","time":"2001-01-01T01:01:08Z"}`,
	}
	gotJSON := strings.Split(strings.TrimSpace(buf.String()), "\n")

	assert.Equal(t, len(wantJSON), len(gotJSON))
	for i := range len(wantJSON) {
		assert.JSONEq(t, wantJSON[i], gotJSON[i])
	}
}

func mustParseTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

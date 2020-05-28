package main

import (
	"bytes"
	"testing"
)

func TestSortedCompactJson(t *testing.T) {
	var tests = []struct {
		testInput      []byte
		expectedOutput []byte
	}{
		{
			testInput:      []byte(`{}`),
			expectedOutput: []byte(`{}`),
		},
	}

	for _, test := range tests {
		out, err := getSortedCompactJSON(test.testInput)
		if err != nil {
			t.Errorf("getSortedCompactJSON returned error: %v", err)
		}
		if !bytes.Equal(out, test.expectedOutput) {
			t.Errorf("getSortedCompactJSON did not return expected output: %v", err)
		}
	}
}

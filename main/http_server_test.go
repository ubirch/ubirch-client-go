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
			testInput: []byte(`{
  "id": "xyz",
  "ts": 1590666587,
  "big": 781829421797092,
  "lst_n": [
    430954646,
    229,
    16978,
    9
  ],
  "lst_l": [
    "Ä",
    "ö",
    "F",
    "c"
  ],
  "map": {
    "A": 0,
    "Ö": 38572,
    "f": 49,
    "ä": 2377016991
  }
}`),
			expectedOutput: []byte(`{"big":781829421797092,"id":"xyz","lst_l":["Ä","ö","F","c"],"lst_n":[430954646,229,16978,9],"map":{"A":0,"f":49,"Ö":38572,"ä":2377016991},"ts":1590666587}`),
		},
	}

	for _, test := range tests {
		out, err := getSortedCompactJSON(test.testInput)
		if err != nil {
			t.Errorf("getSortedCompactJSON returned error: %v", err)
		}
		if !bytes.Equal(out, test.expectedOutput) {
			t.Errorf("getSortedCompactJSON did not return expected output:\n"+
				"- expected: %s\n"+
				"-      got: %s", test.expectedOutput, out)
		}
	}
}

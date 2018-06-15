// Copyright 2018 The InjectSec Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package injectsec

import "testing"

func TestDetector(t *testing.T) {
	maker := NewDetectorMaker()
	detector := maker.Make()
	detector.SkipRegex = true

	attacks := []string{
		"test or 1337=1337 --\"",
		" or 1=1 ",
		"/**/or/**/1337=1337",
	}
	for _, s := range attacks {
		probability, err := detector.Detect(s)
		if err != nil {
			t.Fatal(err)
		}
		if probability < 50 {
			t.Fatal("should be a sql injection attack")
		}
	}

	notAttacks := []string{
		"abc123",
		"abc123 123abc",
		"123",
		"abcorabc",
		"available",
		"orcat1",
		"cat1or",
		"cat1orcat1",
	}
	for _, s := range notAttacks {
		probability, err := detector.Detect(s)
		if err != nil {
			t.Fatal(err)
		}
		if probability > 50 {
			t.Fatal("should not be a sql injection attack")
		}
	}
}

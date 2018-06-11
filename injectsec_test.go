// Copyright 2018 The InjectSec Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package injectsec

import "testing"

func TestDetector(t *testing.T) {
	maker := NewDetectorMaker()
	detector := maker.Make()
	probability, err := detector.Detect("test or 1337=1337 --\"")
	if err != nil {
		t.Fatal(err)
	}
	if probability < 50 {
		t.Fatal("should be a sql injection attack")
	}

	probability, err = detector.Detect("abc123")
	if err != nil {
		t.Fatal(err)
	}
	if probability > 50 {
		t.Fatal("should not be a sql injection attack")
	}

	probability, err = detector.Detect("abc123 123abc")
	if err != nil {
		t.Fatal(err)
	}
	if probability > 50 {
		t.Fatal("should not be a sql injection attack")
	}

	probability, err = detector.Detect("123")
	if err != nil {
		t.Fatal(err)
	}
	if probability > 50 {
		t.Fatal("should not be a sql injection attack")
	}

	probability, err = detector.Detect("abcorabc")
	if err != nil {
		t.Fatal(err)
	}
	if probability > 50 {
		t.Fatal("should not be a sql injection attack")
	}

	probability, err = detector.Detect("available")
	if err != nil {
		t.Fatal(err)
	}
	if probability > 50 {
		t.Fatal("should not be a sql injection attack")
	}
}

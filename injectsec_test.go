// Copyright 2018 The InjectSec Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package injectsec

import "testing"

func TestDetector(t *testing.T) {
	maker := NewDetectorMaker()
	detector := maker.Make()
	if detector.Detect("test or 1337=1337 --\"") != true {
		t.Fatal("should be a sql injection attack")
	}
	if detector.Detect("abc123") != false {
		t.Fatal("should not be a sql injection attack")
	}
	if detector.Detect("abc123 123abc") != false {
		t.Fatal("should not be a sql injection attack")
	}
	if detector.Detect("123") != false {
		t.Fatal("should not be a sql injection attack")
	}
	if detector.Detect("abcorabc") != false {
		t.Fatal("should not be a sql injection attack")
	}
	if detector.Detect("available") != false {
		t.Fatal("should not be a sql injection attack")
	}
}

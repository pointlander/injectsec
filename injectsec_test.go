// Copyright 2018 The InjectSec Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package injectsec

import "testing"

func TestDetector(t *testing.T) {
	detector := NewDetector()
	if detector.DetectString("test or 1337=1337 --\"") != true {
		t.Fatal("should be a sql injection attack")
	}
	if detector.DetectString("abc123") != false {
		t.Fatal("should not be a sql injection attack")
	}
	if detector.DetectString("abc123 123abc") != false {
		t.Fatal("should not be a sql injection attack")
	}
}

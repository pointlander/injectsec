// Copyright 2018 The InjectSec Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package injectsec

import (
	"bytes"
	"strings"

	"github.com/pointlander/injectsec/gru"
)

// Detector detects SQL injection attacks
type Detector struct {
	*gru.Detector
}

// NewDetector creates a new detector
func NewDetector() *Detector {
	detector := gru.NewDetector()
	weights, err := ReadFile("weights.w")
	if err != nil {
		panic(err)
	}
	err = detector.Read(bytes.NewBuffer(weights))
	if err != nil {
		panic(err)
	}
	return &Detector{
		Detector: detector,
	}
}

// DetectString tests if a string is a SQL injection attack
func (d *Detector) DetectString(a string) bool {
	return d.Detect([]byte(strings.ToLower(a)))
}

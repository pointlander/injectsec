// Copyright 2018 The InjectSec Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

// PartType is a type of a part
type PartType int

const (
	// PartTypeLiteral is a literal part type
	PartTypeLiteral PartType = iota
	// PartTypeNumber is a number
	PartTypeNumber
	// PartTypeName is a name
	PartTypeName
	// PartTypeOr is a or part type with spaces
	PartTypeOr
	// PartTypeHexOr is a or parth type with hex sampleSpaces
	PartTypeHexOr
	// PartTypeSpaces represents spaces
	PartTypeSpaces
	// PartTypeObfuscated is an obfuscated string
	PartTypeObfuscated
	// PartTypeHex is a hex string
	PartTypeHex
)

// Part is part of a regex
type Part struct {
	PartType
	Variable int
	Literal  string
	Max      int
	Parts    *Parts
}

// Parts is a bunch of Part
type Parts struct {
	Parts []Part
}

// NewParts creates a new set of parts
func NewParts() *Parts {
	return &Parts{
		Parts: make([]Part, 0, 16),
	}
}

// AddType adds a part with type to the parts
func (p *Parts) AddType(partType PartType) {
	part := Part{
		PartType: partType,
	}
	p.Parts = append(p.Parts, part)
	return
}

// AddParts adds parts
func (p *Parts) AddParts(partType PartType, adder func(p *Parts)) {
	part := Part{
		PartType: partType,
		Parts:    NewParts(),
	}
	adder(part.Parts)
	p.Parts = append(p.Parts, part)
}

// AddLiteral adds a literal to the parts
func (p *Parts) AddLiteral(literal string) {
	part := Part{
		PartType: PartTypeLiteral,
		Literal:  literal,
	}
	p.Parts = append(p.Parts, part)
	return
}

// AddNumber adds a literal to the parts
func (p *Parts) AddNumber(variable, max int) {
	part := Part{
		PartType: PartTypeLiteral,
		Variable: variable,
		Max:      max,
	}
	p.Parts = append(p.Parts, part)
	return
}

// AddName adss a PartTypeName
func (p *Parts) AddName(variable int) {
	part := Part{
		PartType: PartTypeName,
		Variable: variable,
	}
	p.Parts = append(p.Parts, part)
	return
}

// AddOr adds a part type or
func (p *Parts) AddOr() {
	p.AddType(PartTypeOr)
}

// AddHexOr adds a part type hex or
func (p *Parts) AddHexOr() {
	p.AddType(PartTypeHexOr)
}

// AddSpaces adds a part type spaces
func (p *Parts) AddSpaces() {
	p.AddType(PartTypeSpaces)
}

// AddHex adds a hex type
func (p *Parts) AddHex(max int) {
	part := Part{
		PartType: PartTypeHex,
		Max:      max,
	}
	p.Parts = append(p.Parts, part)
}

// AddBenchmark add a SQL benchmark statement
func (p *Parts) AddBenchmark() {
	p.AddLiteral("benchmark(")
	p.AddSpaces()
	p.AddNumber(0, 10000000)
	p.AddSpaces()
	p.AddLiteral(",MD5(")
	p.AddSpaces()
	p.AddNumber(1, 10000000)
	p.AddLiteral("))#")
}

// AddWaitfor adds a waitfor statement
func (p *Parts) AddWaitfor() {
	p.AddLiteral(";waitfor")
	p.AddSpaces()
	p.AddLiteral("delay")
	p.AddSpaces()
	p.AddLiteral("'")
	p.AddNumber(0, 24)
	p.AddLiteral(":")
	p.AddNumber(1, 60)
	p.AddLiteral(":")
	p.AddNumber(2, 60)
	p.AddLiteral("'--")
}

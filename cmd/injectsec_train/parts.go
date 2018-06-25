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
	// PartTypeHexOr is a or part type with hex spaces
	PartTypeHexOr
	// PartTypeAnd is a and part type with spaces
	PartTypeAnd
	// PartTypeSpaces represents spaces
	PartTypeSpaces
	// PartTypeSpacesOptional represents spaces or nothing
	PartTypeSpacesOptional
	// PartTypeHexSpaces represents hex spaces
	PartTypeHexSpaces
	// PartTypeComment represents a comment
	PartTypeComment
	// PartTypeObfuscated is an obfuscated string
	PartTypeObfuscated
	// PartTypeHex is a hex string
	PartTypeHex
	// PartTypeNumberList is a list of numbers
	PartTypeNumberList
	// PartTypeScientificNumber is a sciencetific number
	PartTypeScientificNumber
	// PartTypeSQL is a sql part type
	PartTypeSQL
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

// AddAnd adds a part type and
func (p *Parts) AddAnd() {
	p.AddType(PartTypeAnd)
}

// AddSpaces adds a part type spaces
func (p *Parts) AddSpaces() {
	p.AddType(PartTypeSpaces)
}

// AddSpacesOptional adds a part type spaces optional
func (p *Parts) AddSpacesOptional() {
	p.AddType(PartTypeSpacesOptional)
}

// AddHexSpaces adds a part type hex spaces
func (p *Parts) AddHexSpaces() {
	p.AddType(PartTypeHexSpaces)
}

// AddComment adds a part type comment
func (p *Parts) AddComment() {
	p.AddType(PartTypeComment)
}

// AddHex adds a hex type
func (p *Parts) AddHex(max int) {
	part := Part{
		PartType: PartTypeHex,
		Max:      max,
	}
	p.Parts = append(p.Parts, part)
}

// AddNumberList adds a list of numbers
func (p *Parts) AddNumberList(max int) {
	part := Part{
		PartType: PartTypeNumberList,
		Max:      max,
	}
	p.Parts = append(p.Parts, part)
}

// AddBenchmark add a SQL benchmark statement
func (p *Parts) AddBenchmark() {
	p.AddLiteral("benchmark(")
	p.AddSpaces()
	p.AddNumber(1024, 10000000)
	p.AddSpaces()
	p.AddLiteral(",MD5(")
	p.AddSpaces()
	p.AddNumber(1025, 10000000)
	p.AddLiteral("))#")
}

// AddWaitfor adds a waitfor statement
func (p *Parts) AddWaitfor() {
	p.AddLiteral(";waitfor")
	p.AddSpaces()
	p.AddLiteral("delay")
	p.AddSpaces()
	p.AddLiteral("'")
	p.AddNumber(1024, 24)
	p.AddLiteral(":")
	p.AddNumber(1025, 60)
	p.AddLiteral(":")
	p.AddNumber(1026, 60)
	p.AddLiteral("'--")
}

// AddSQL adds a part type SQL
func (p *Parts) AddSQL() {
	p.AddType(PartTypeSQL)
}

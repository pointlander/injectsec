// Copyright 2018 The InjectSec Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"math/rand"
	"strconv"
)

// Generator generates training data
type Generator struct {
	Form     string
	Skip     bool
	Abstract bool
	Make     func() (sample string)
	Regex    func() *Parts
}

// TrainingDataGenerator returns a data generator
func TrainingDataGenerator(rnd *rand.Rand) []Generator {
	sampleHexSpaces := func() string {
		sample, count := "", rnd.Intn(5)+1
		for i := 0; i < count; i++ {
			sample += "%20"
		}
		return sample
	}
	sampleSpaces := func() string {
		sample, count := "", rnd.Intn(5)+1
		for i := 0; i < count; i++ {
			sample += " "
		}
		return sample
	}
	sampleOr := func() string {
		if rnd.Intn(2) == 0 {
			return "or"
		}
		return "||"
	}
	sampleAnd := func() string {
		if rnd.Intn(2) == 0 {
			return "and"
		}
		return "&&"
	}
	sampleName := func() string {
		sample, count := "", rand.Intn(8)+1
		for i := 0; i < count; i++ {
			sample += string(rune(int('a') + rnd.Intn(int('z'-'a'))))
		}
		return sample
	}
	sampleNumber := func(a int) string {
		return strconv.Itoa(rand.Intn(a))
	}
	sampleHex := func(a int) string {
		return fmt.Sprintf("%#x", rnd.Intn(a))
	}

	sampleBenchmark := func() (sample string) {
		sample += "benchmark("
		sample += sampleNumber(10000000)
		sample += ",MD5("
		sample += sampleNumber(10000000)
		sample += "))#"
		return
	}
	generators := []Generator{
		// Generic-SQLi.txt
		{
			Form: ")%20or%20('x'='x",
			Make: func() (sample string) {
				sample += ")"
				sample += sampleHexSpaces()
				sample += sampleOr()
				sample += sampleHexSpaces()
				sample += "('"
				name := sampleName()
				sample += name
				sample += "'='"
				sample += name
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral(")")
				p.AddHexOr()
				p.AddLiteral("('")
				p.AddName(0)
				p.AddLiteral("'='")
				p.AddName(0)
				return p
			},
		},
		{
			Form: "%20or%201=1",
			Make: func() (sample string) {
				sample += sampleHexSpaces()
				sample += sampleOr()
				sample += sampleHexSpaces()
				number := sampleNumber(1337)
				sample += number
				sample += "="
				sample += number
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddHexOr()
				p.AddNumber(0, 1337)
				p.AddLiteral("=")
				p.AddNumber(0, 1337)
				return p
			},
		},
		{
			Form: "; execute immediate 'sel' || 'ect us' || 'er'",
			Make: func() (sample string) {
				sample += "; execute immediate '"
				concat := "select " + sampleName()
				for _, v := range concat {
					sample += string(v)
					if rnd.Intn(3) == 0 {
						sample += "' || '"
					}
				}
				sample += "'"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral(";")
				p.AddSpaces()
				p.AddLiteral("execute")
				p.AddSpaces()
				p.AddLiteral("immediate")
				p.AddSpaces()
				p.AddParts(PartTypeObfuscated, func(p *Parts) {
					p.AddLiteral("select")
					p.AddSpaces()
					p.AddName(0)
				})
				return p
			},
		},
		{
			Form: "benchmark(10000000,MD5(1))#",
			Make: func() (sample string) {
				sample += sampleBenchmark()
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddBenchmark()
				return p
			},
		},
		{
			Form: "update",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += "update"
				sample += sampleSpaces()
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpacesOptional()
				p.AddLiteral("update")
				p.AddSpacesOptional()
				return p
			},
		},
		{
			Form:     "\";waitfor delay '0:0:__TIME__'--",
			Abstract: true,
			Make: func() (sample string) {
				sample += "\";waitfor"
				sample += sampleSpaces()
				sample += "delay"
				sample += sampleSpaces()
				sample += "'"
				sample += sampleNumber(24)
				sample += ":"
				sample += sampleNumber(60)
				sample += ":"
				sample += sampleNumber(60)
				sample += "'--"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("\"")
				p.AddWaitfor()
				return p
			},
		},
		{
			Form:     "1) or pg_sleep(__TIME__)--",
			Abstract: true,
			Make: func() (sample string) {
				sample += sampleNumber(1337)
				sample += ")"
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += "pg_sleep("
				sample += sampleNumber(1337)
				sample += ")--"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddNumber(0, 1337)
				p.AddLiteral(")")
				p.AddOr()
				p.AddLiteral("pg_sleep(")
				p.AddNumber(1, 1337)
				p.AddLiteral(")--")
				return p
			},
		},
		{
			Form: "||(elt(-3+5,bin(15),ord(10),hex(char(45))))",
			Make: func() (sample string) {
				sample += sampleOr()
				sample += "(elt("
				sample += sampleNumber(1337)
				sample += ",bin("
				sample += sampleNumber(1337)
				sample += "),ord("
				sample += sampleNumber(10)
				sample += "),hex(char("
				sample += sampleNumber(256)
				sample += "))))"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddOr()
				p.AddLiteral("(elt(")
				p.AddNumber(0, 1337)
				p.AddLiteral(",bin(")
				p.AddNumber(1, 1337)
				p.AddLiteral("),ord(")
				p.AddNumber(2, 10)
				p.AddLiteral("),hex(char(")
				p.AddNumber(3, 256)
				p.AddLiteral("))))")
				return p
			},
		},
		{
			Form: "\"hi\"\") or (\"\"a\"\"=\"\"a\"",
			Make: func() (sample string) {
				sample += "\""
				sample += sampleName()
				sample += "\"\")"
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += "(\"\""
				name := sampleName()
				sample += name
				sample += "\"\"=\"\""
				sample += name
				sample += "\""
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("\"")
				p.AddName(0)
				p.AddLiteral("\"\")")
				p.AddOr()
				p.AddLiteral("(\"\"")
				p.AddName(1)
				p.AddLiteral("\"\"=\"\"")
				p.AddName(1)
				p.AddLiteral("\"")
				return p
			},
		},
		{
			Form: "delete",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += "delete"
				sample += sampleSpaces()
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpacesOptional()
				p.AddLiteral("delete")
				p.AddSpacesOptional()
				return p
			},
		},
		{
			Form: "like",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += "like"
				sample += sampleSpaces()
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpacesOptional()
				p.AddLiteral("like")
				p.AddSpacesOptional()
				return p
			},
		},
		{
			Form:     "\" or sleep(__TIME__)#",
			Abstract: true,
			Make: func() (sample string) {
				sample += "\""
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += "sleep("
				sample += sampleNumber(1337)
				sample += ")#"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("\"")
				p.AddOr()
				p.AddLiteral("sleep(")
				p.AddNumber(0, 1337)
				p.AddLiteral(")#")
				return p
			},
		},
		{
			Form:     "pg_sleep(__TIME__)--",
			Abstract: true,
			Make: func() (sample string) {
				sample += "pg_sleep("
				sample += sampleNumber(1337)
				sample += ")--"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("pg_sleep(")
				p.AddNumber(0, 1337)
				p.AddLiteral(")--")
				return p
			},
		},
		{
			Form: "*(|(objectclass=*))",
		},
		{
			Form:     "declare @q nvarchar (200) 0x730065006c00650063 ...",
			Abstract: true,
			Make: func() (sample string) {
				sample += "declare"
				sample += sampleSpaces()
				sample += "@"
				sample += sampleName()
				sample += sampleSpaces()
				sample += "nvarchar"
				sample += sampleSpaces()
				sample += "("
				sample += sampleNumber(1337)
				sample += ")"
				sample += sampleSpaces()
				sample += sampleHex(1337 * 1337)
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("declare")
				p.AddSpaces()
				p.AddLiteral("@")
				p.AddName(0)
				p.AddSpaces()
				p.AddLiteral("nvarchar")
				p.AddSpaces()
				p.AddLiteral("(")
				p.AddNumber(1, 1337)
				p.AddLiteral(")")
				p.AddSpaces()
				p.AddHex(1337 * 1337)
				return p
			},
		},
		{
			Form: " or 0=0 #",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				number := sampleNumber(1337)
				sample += number
				sample += "="
				sample += number
				sample += sampleSpaces()
				sample += "#"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddOr()
				p.AddNumber(0, 1337)
				p.AddLiteral("=")
				p.AddNumber(0, 1337)
				p.AddSpaces()
				p.AddLiteral("#")
				return p
			},
		},
		{
			Form: "insert",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += "insert"
				sample += sampleSpaces()
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpacesOptional()
				p.AddLiteral("insert")
				p.AddSpacesOptional()
				return p
			},
		},
		{
			Form:     "1) or sleep(__TIME__)#",
			Abstract: true,
			Make: func() (sample string) {
				sample += sampleNumber(1337)
				sample += ")"
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += "sleep("
				sample += sampleNumber(1337)
				sample += ")#"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddNumber(0, 1337)
				p.AddLiteral(")")
				p.AddOr()
				p.AddLiteral("sleep(")
				p.AddNumber(1, 1337)
				p.AddLiteral(")#")
				return p
			},
		},
		{
			Form: ") or ('a'='a",
			Make: func() (sample string) {
				sample += ")"
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += "('"
				name := sampleName()
				sample += name
				sample += "'='"
				sample += name
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral(")")
				p.AddOr()
				p.AddLiteral("('")
				p.AddName(0)
				p.AddLiteral("'='")
				p.AddName(0)
				return p
			},
		},
		{
			Form: "; exec xp_regread",
			Make: func() (sample string) {
				sample += ";"
				sample += sampleSpaces()
				sample += "exec"
				sample += sampleSpaces()
				sample += "xp_regread"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral(";")
				p.AddSpaces()
				p.AddLiteral("exec")
				p.AddSpaces()
				p.AddLiteral("xp_regread")
				return p
			},
		},
		{
			Form: "*|",
		},
		{
			Form: "@var select @var as var into temp end --",
			Make: func() (sample string) {
				sample += "@"
				name := sampleName()
				sample += name
				sample += sampleSpaces()
				sample += "select"
				sample += sampleSpaces()
				sample += "@"
				sample += name
				sample += sampleSpaces()
				sample += "as"
				sample += sampleSpaces()
				sample += name
				sample += sampleSpaces()
				sample += "into"
				sample += sampleSpaces()
				sample += sampleName()
				sample += sampleSpaces()
				sample += "end"
				sample += sampleSpaces()
				sample += "--"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("@")
				p.AddName(0)
				p.AddSpaces()
				p.AddLiteral("select")
				p.AddSpaces()
				p.AddLiteral("@")
				p.AddName(0)
				p.AddSpaces()
				p.AddLiteral("as")
				p.AddSpaces()
				p.AddName(0)
				p.AddSpaces()
				p.AddLiteral("into")
				p.AddSpaces()
				p.AddName(1)
				p.AddSpaces()
				p.AddLiteral("end")
				p.AddSpaces()
				return p
			},
		},
		{
			Form: "1)) or benchmark(10000000,MD5(1))#",
			Make: func() (sample string) {
				sample += sampleNumber(1337)
				sample += "))"
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += sampleBenchmark()
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddNumber(0, 1337)
				p.AddLiteral("))")
				p.AddOr()
				p.AddBenchmark()
				return p
			},
		},
		{
			Form: "asc",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += "asc"
				sample += sampleSpaces()
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpacesOptional()
				p.AddLiteral("asc")
				p.AddSpacesOptional()
				return p
			},
		},
		{
			Form: "(||6)",
			Make: func() (sample string) {
				sample += "(||"
				sample += sampleNumber(1337)
				sample += ")"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("(||")
				p.AddNumber(0, 1337)
				p.AddLiteral(")")
				return p
			},
		},
		{
			Form: "\"a\"\" or 3=3--\"",
			Make: func() (sample string) {
				sample += "\""
				sample += sampleName()
				sample += "\"\""
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				number := sampleNumber(1337)
				sample += number
				sample += "="
				sample += number
				sample += "--\""
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("\"")
				p.AddName(0)
				p.AddLiteral("\"\"")
				p.AddOr()
				p.AddNumber(1, 1337)
				p.AddLiteral("=")
				p.AddNumber(1, 1337)
				p.AddLiteral("--\"")
				return p
			},
		},
		{
			Form: "\" or benchmark(10000000,MD5(1))#",
			Make: func() (sample string) {
				sample += "\""
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += sampleBenchmark()
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("\"")
				p.AddOr()
				p.AddBenchmark()
				return p
			},
		},
		{
			Form: "# from wapiti",
			Make: func() (sample string) {
				sample += "#"
				sample += sampleSpaces()
				sample += "from"
				sample += sampleSpaces()
				sample += "wapiti"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("#")
				p.AddSpaces()
				p.AddLiteral("from")
				p.AddSpaces()
				p.AddLiteral("wapiti")
				return p
			},
		},
		{
			Form: " or 0=0 --",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				number := sampleNumber(1337)
				sample += number
				sample += "="
				sample += number
				sample += sampleSpaces()
				sample += "--"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddOr()
				p.AddNumber(0, 1337)
				p.AddLiteral("=")
				p.AddNumber(0, 1337)
				p.AddSpaces()
				p.AddLiteral("--")
				return p
			},
		},
		{
			Form: "1 waitfor delay '0:0:10'--",
			Make: func() (sample string) {
				sample += sampleNumber(1337)
				sample += sampleSpaces()
				sample += "waitfor"
				sample += sampleSpaces()
				sample += "delay"
				sample += sampleSpaces()
				sample += "'"
				sample += sampleNumber(24)
				sample += ":"
				sample += sampleNumber(60)
				sample += ":"
				sample += sampleNumber(60)
				sample += "'--"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddNumber(0, 1337)
				p.AddSpaces()
				p.AddLiteral("waitfor")
				p.AddSpaces()
				p.AddLiteral("delay")
				p.AddSpaces()
				p.AddLiteral("'")
				p.AddNumber(1, 24)
				p.AddLiteral(":")
				p.AddNumber(2, 60)
				p.AddLiteral(":")
				p.AddNumber(3, 60)
				p.AddLiteral("'--")
				return p
			},
		},
		{
			Form: " or 'a'='a",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += "'"
				name := sampleName()
				sample += name
				sample += "'='"
				sample += name
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddOr()
				p.AddLiteral("'")
				p.AddName(0)
				p.AddLiteral("'='")
				p.AddName(0)
				return p
			},
		},
		{
			Form: "hi or 1=1 --\"",
			Make: func() (sample string) {
				sample += sampleName()
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				number := sampleNumber(1337)
				sample += number
				sample += "="
				sample += number
				sample += sampleSpaces()
				sample += "--\""
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddName(0)
				p.AddOr()
				p.AddNumber(1, 1337)
				p.AddLiteral("=")
				p.AddNumber(1, 1337)
				p.AddSpaces()
				p.AddLiteral("--\"")
				return p
			},
		},
		{
			Form: "or a = a",
			Make: func() (sample string) {
				sample += sampleOr()
				sample += sampleSpaces()
				name := sampleName()
				sample += name
				sample += sampleSpaces()
				sample += "="
				sample += sampleSpaces()
				sample += name
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddOr()
				p.AddName(0)
				p.AddSpaces()
				p.AddLiteral("=")
				p.AddSpaces()
				p.AddName(0)
				return p
			},
		},
		{
			Form: " UNION ALL SELECT",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += "union"
				sample += sampleSpaces()
				sample += "all"
				sample += sampleSpaces()
				sample += "select"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpaces()
				p.AddLiteral("union")
				p.AddSpaces()
				p.AddLiteral("all")
				p.AddSpaces()
				p.AddLiteral("select")
				return p
			},
		},
		{
			Form:     ") or sleep(__TIME__)='",
			Abstract: true,
			Make: func() (sample string) {
				sample += ")"
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += "sleep("
				sample += sampleNumber(1337)
				sample += ")='"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral(")")
				p.AddOr()
				p.AddLiteral("sleep(")
				p.AddNumber(0, 1337)
				p.AddLiteral(")='")
				return p
			},
		},
		{
			Form: ")) or benchmark(10000000,MD5(1))#",
			Make: func() (sample string) {
				sample += "))"
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += sampleBenchmark()
				sample += "#"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("))")
				p.AddOr()
				p.AddBenchmark()
				return p
			},
		},
		{
			Form: "hi' or 'a'='a",
			Make: func() (sample string) {
				sample += sampleName()
				sample += "'"
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += "'"
				name := sampleName()
				sample += name
				sample += "'='"
				sample += name
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddName(0)
				p.AddLiteral("'")
				p.AddOr()
				p.AddLiteral("'")
				p.AddName(1)
				p.AddLiteral("'='")
				p.AddName(1)
				return p
			},
		},
		{
			Form: "0",
			Skip: true,
			Make: func() (sample string) {
				sample += sampleNumber(1337)
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddNumber(0, 1337)
				return p
			},
		},
		{
			Form: "21 %",
			Make: func() (sample string) {
				sample += sampleNumber(1337)
				sample += sampleSpaces()
				sample += "%"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddNumber(0, 1337)
				p.AddSpaces()
				p.AddLiteral("%")
				return p
			},
		},
		{
			Form: "limit",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += "limit"
				sample += sampleSpaces()
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpacesOptional()
				p.AddLiteral("limit")
				p.AddSpacesOptional()
				return p
			},
		},
		{
			Form: " or 1=1",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				number := sampleNumber(1337)
				sample += number
				sample += "="
				sample += number
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddOr()
				p.AddNumber(0, 1337)
				p.AddLiteral("=")
				p.AddNumber(0, 1337)
				return p
			},
		},
		{
			Form: " or 2 > 1",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				number := sampleNumber(1337)
				sample += number
				sample += sampleSpaces()
				sample += ">"
				sample += sampleSpaces()
				max, err := strconv.Atoi(number)
				if err != nil {
					panic(err)
				}
				sample += sampleNumber(max)
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddOr()
				p.AddNumber(0, 1337)
				p.AddSpaces()
				p.AddLiteral(">")
				p.AddSpaces()
				p.AddNumber(0, 1337)
				return p
			},
		},
		{
			Form: "\")) or benchmark(10000000,MD5(1))#",
			Make: func() (sample string) {
				sample += "\"))"
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += sampleBenchmark()
				sample += "#"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("\"))")
				p.AddOr()
				p.AddBenchmark()
				return p
			},
		},
		{
			Form: "PRINT",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += "print"
				sample += sampleSpaces()
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpacesOptional()
				p.AddLiteral("print")
				p.AddSpacesOptional()
				return p
			},
		},
		{
			Form: "hi') or ('a'='a",
			Make: func() (sample string) {
				sample += sampleName()
				sample += "')"
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += "('"
				name := sampleName()
				sample += name
				sample += "'='"
				sample += name
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddName(0)
				p.AddLiteral("')")
				p.AddOr()
				p.AddLiteral("('")
				p.AddName(1)
				p.AddLiteral("'='")
				p.AddName(1)
				return p
			},
		},
		{
			Form: " or 3=3",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				number := sampleNumber(1337)
				sample += number
				sample += "="
				sample += number
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddOr()
				p.AddNumber(0, 1337)
				p.AddLiteral("=")
				p.AddNumber(0, 1337)
				return p
			},
		},
		{
			Form:     "));waitfor delay '0:0:__TIME__'--",
			Abstract: true,
			Make: func() (sample string) {
				sample += "));waitfor"
				sample += sampleSpaces()
				sample += "delay"
				sample += sampleSpaces()
				sample += "'"
				sample += sampleNumber(24)
				sample += ":"
				sample += sampleNumber(60)
				sample += ":"
				sample += sampleNumber(60)
				sample += "'--'"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("))")
				p.AddWaitfor()
				return p
			},
		},
		{
			Form: "a' waitfor delay '0:0:10'--",
			Make: func() (sample string) {
				sample += sampleName()
				sample += "'"
				sample += sampleSpaces()
				sample += "waitfor"
				sample += sampleSpaces()
				sample += "delay"
				sample += sampleSpaces()
				sample += "'"
				sample += sampleNumber(24)
				sample += ":"
				sample += sampleNumber(60)
				sample += ":"
				sample += sampleNumber(60)
				sample += "'--"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddName(0)
				p.AddLiteral("'")
				p.AddSpaces()
				p.AddLiteral("waitfor")
				p.AddSpaces()
				p.AddLiteral("delay")
				p.AddSpaces()
				p.AddLiteral("'")
				p.AddNumber(1, 24)
				p.AddLiteral(":")
				p.AddNumber(2, 60)
				p.AddLiteral(":")
				p.AddNumber(3, 60)
				p.AddLiteral("'--")
				return p
			},
		},
		{
			Form:     "1;(load_file(char(47,101,116,99,47,112,97,115, ...",
			Abstract: true,
			Make: func() (sample string) {
				sample += sampleNumber(256)
				sample += ";(load_file(char("
				for i := 0; i < 7; i++ {
					sample += sampleNumber(256)
					sample += ","
				}
				sample += sampleNumber(256)
				sample += ")))"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddNumber(0, 256)
				p.AddLiteral(";(load_file(char(")
				p.AddNumberList(256)
				p.AddLiteral(")))")
				return p
			},
		},
		{
			Form: "or%201=1",
			Make: func() (sample string) {
				sample += sampleOr()
				sample += sampleHexSpaces()
				number := sampleNumber(1337)
				sample += number
				sample += "="
				sample += number
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddHexOr()
				p.AddNumber(0, 1337)
				p.AddLiteral("=")
				p.AddNumber(0, 1337)
				return p
			},
		},
		{
			Form:     "1 or sleep(__TIME__)#",
			Abstract: true,
			Make: func() (sample string) {
				sample += sampleNumber(1337)
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += "sleep("
				sample += sampleNumber(1337)
				sample += ")#"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddNumber(0, 1337)
				p.AddOr()
				p.AddLiteral("sleep(")
				p.AddSpaces()
				p.AddNumber(1, 1337)
				p.AddSpaces()
				p.AddLiteral(")#")
				return p
			},
		},
		{
			Form: "or 1=1",
			Make: func() (sample string) {
				sample += sampleOr()
				sample += sampleSpaces()
				number := sampleNumber(1337)
				sample += number
				sample += "="
				sample += number
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddOr()
				p.AddNumber(0, 1337)
				p.AddLiteral("=")
				p.AddNumber(0, 1337)
				return p
			},
		},
		{
			Form: " and 1 in (select var from temp)--",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += sampleAnd()
				sample += sampleSpaces()
				sample += sampleNumber(1337)
				sample += sampleSpaces()
				sample += "in"
				sample += sampleSpaces()
				sample += "(select"
				sample += sampleSpaces()
				sample += sampleName()
				sample += sampleSpaces()
				sample += "from"
				sample += sampleSpaces()
				sample += sampleName()
				sample += ")--"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddAnd()
				p.AddNumber(0, 1337)
				p.AddSpaces()
				p.AddLiteral("in")
				p.AddSpaces()
				p.AddLiteral("(select")
				p.AddSpaces()
				p.AddName(1)
				p.AddSpaces()
				p.AddLiteral("from")
				p.AddSpaces()
				p.AddName(2)
				p.AddLiteral(")--")
				return p
			},
		},
		{
			Form: " or '7659'='7659",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += "'"
				number := sampleNumber(1337)
				sample += number
				sample += "'='"
				sample += number
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddOr()
				p.AddLiteral("'")
				p.AddNumber(0, 1337)
				p.AddLiteral("'='")
				p.AddNumber(0, 1337)
				return p
			},
		},
		{
			Form: " or 'text' = n'text'",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += "'"
				name := sampleName()
				sample += name
				sample += "'"
				sample += sampleSpaces()
				sample += "="
				sample += sampleSpaces()
				sample += "n'"
				sample += name
				sample += "'"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddOr()
				p.AddLiteral("'")
				p.AddName(0)
				p.AddLiteral("'")
				p.AddSpaces()
				p.AddLiteral("=")
				p.AddSpaces()
				p.AddLiteral("n'")
				p.AddName(0)
				p.AddLiteral("'")
				return p
			},
		},
		{
			Form: " --",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += "--"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpacesOptional()
				p.AddLiteral("--")
				return p
			},
		},
		{
			Form: " or 1=1 or ''='",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				number := sampleNumber(1337)
				sample += number
				sample += "="
				sample += number
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += "''='"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddOr()
				p.AddNumber(0, 1337)
				p.AddLiteral("=")
				p.AddNumber(0, 1337)
				p.AddOr()
				p.AddLiteral("''='")
				return p
			},
		},
		{
			Form:     "declare @s varchar (200) select @s = 0x73656c6 ...",
			Abstract: true,
			Make: func() (sample string) {
				sample += "declare"
				sample += sampleSpaces()
				sample += "@"
				name := sampleName()
				sample += name
				sample += sampleSpaces()
				sample += "varchar"
				sample += sampleSpaces()
				sample += "("
				sample += sampleNumber(200)
				sample += ")"
				sample += sampleSpaces()
				sample += "select"
				sample += sampleSpaces()
				sample += "@"
				sample += name
				sample += sampleSpaces()
				sample += "="
				sample += sampleSpaces()
				sample += sampleHex(1337 * 1337)
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("declare")
				p.AddSpaces()
				p.AddLiteral("@")
				p.AddName(0)
				p.AddSpaces()
				p.AddLiteral("varchar")
				p.AddSpaces()
				p.AddLiteral("(")
				p.AddNumber(1, 200)
				p.AddLiteral(")")
				p.AddSpaces()
				p.AddLiteral("select")
				p.AddSpaces()
				p.AddLiteral("@")
				p.AddName(0)
				p.AddSpaces()
				p.AddLiteral("=")
				p.AddSpaces()
				p.AddHex(1337 * 1337)
				return p
			},
		},
		{
			Form: "exec xp",
			Make: func() (sample string) {
				sample += "exec"
				sample += sampleSpaces()
				sample += sampleName()
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("exec")
				p.AddSpaces()
				p.AddName(0)
				return p
			},
		},
		{
			Form: "; exec master..xp_cmdshell 'ping 172.10.1.255'--",
			Make: func() (sample string) {
				sample += ";"
				sample += sampleSpaces()
				sample += "exec"
				sample += sampleSpaces()
				sample += "master..xp_cmdshell"
				sample += sampleSpaces()
				sample += "'ping"
				sample += sampleSpaces()
				sample += sampleNumber(256)
				sample += "."
				sample += sampleNumber(256)
				sample += "."
				sample += sampleNumber(256)
				sample += "."
				sample += sampleNumber(256)
				sample += "'--"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral(";")
				p.AddSpaces()
				p.AddLiteral("exec")
				p.AddSpaces()
				p.AddLiteral("master..xp_cmdshell")
				p.AddSpaces()
				p.AddLiteral("'ping")
				p.AddSpaces()
				p.AddNumber(0, 256)
				p.AddLiteral(".")
				p.AddNumber(1, 256)
				p.AddLiteral(".")
				p.AddNumber(2, 256)
				p.AddLiteral(".")
				p.AddNumber(3, 256)
				p.AddLiteral("'--")
				return p
			},
		},
		{
			Form: "3.10E+17",
			Make: func() (sample string) {
				const factor = 1337 * 1337
				sample += fmt.Sprintf("%E", rnd.Float64()*factor-factor/2)
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddType(PartTypeScientificNumber)
				return p
			},
		},
		{
			Form:     "\" or pg_sleep(__TIME__)--",
			Abstract: true,
			Make: func() (sample string) {
				sample += "\""
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += "pg_sleep("
				sample += sampleNumber(1337)
				sample += ")--"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("\"")
				p.AddOr()
				p.AddLiteral("pg_sleep(")
				p.AddNumber(0, 1337)
				p.AddLiteral(")--")
				return p
			},
		},
		{
			Form: "x' AND email IS NULL; --",
			Make: func() (sample string) {
				sample += sampleName()
				sample += "'"
				sample += sampleSpaces()
				sample += sampleAnd()
				sample += sampleSpaces()
				sample += sampleName()
				sample += sampleSpaces()
				sample += "is"
				sample += sampleSpaces()
				sample += "null;"
				sample += sampleSpaces()
				sample += "--"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddName(0)
				p.AddLiteral("'")
				p.AddAnd()
				p.AddName(1)
				p.AddSpaces()
				p.AddLiteral("is")
				p.AddSpaces()
				p.AddLiteral("null;")
				p.AddSpaces()
				p.AddLiteral("--")
				return p
			},
		},
		{
			Form: "&",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += "&"
				sample += sampleSpaces()
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpacesOptional()
				p.AddLiteral("&")
				p.AddSpacesOptional()
				return p
			},
		},
		{
			Form: "admin' or '",
			Make: func() (sample string) {
				sample += sampleName()
				sample += "'"
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += "'"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddName(0)
				p.AddLiteral("'")
				p.AddOr()
				p.AddLiteral("'")
				return p
			},
		},
		{
			Form: " or 'unusual' = 'unusual'",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += "'"
				name := sampleName()
				sample += "'"
				sample += sampleSpaces()
				sample += "="
				sample += sampleSpaces()
				sample += "'"
				sample += name
				sample += "'"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddOr()
				p.AddLiteral("'")
				p.AddName(0)
				p.AddLiteral("'")
				p.AddSpaces()
				p.AddLiteral("=")
				p.AddSpaces()
				p.AddLiteral("'")
				p.AddName(0)
				p.AddLiteral("'")
				return p
			},
		},
		{
			Form: "//",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += "//"
				sample += sampleSpaces()
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpacesOptional()
				p.AddLiteral("//")
				p.AddSpacesOptional()
				return p
			},
		},
		{
			Form: "truncate",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += "truncate"
				sample += sampleSpaces()
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpacesOptional()
				p.AddLiteral("truncate")
				p.AddSpacesOptional()
				return p
			},
		},
		{
			Form: "1) or benchmark(10000000,MD5(1))#",
			Make: func() (sample string) {
				sample += sampleNumber(1337)
				sample += ")"
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += sampleBenchmark()
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddNumber(0, 1337)
				p.AddLiteral(")")
				p.AddOr()
				p.AddBenchmark()
				return p
			},
		},
		{
			Form: "\x27UNION SELECT",
			Make: func() (sample string) {
				sample += "\x27union"
				sample += sampleSpaces()
				sample += "select"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("\x27union")
				p.AddSpaces()
				p.AddLiteral("select")
				return p
			},
		},
		{
			Form:     "declare @s varchar(200) select @s = 0x77616974 ...",
			Abstract: true,
			Make: func() (sample string) {
				sample += "declare"
				sample += sampleSpaces()
				sample += "@"
				name := sampleName()
				sample += name
				sample += sampleSpaces()
				sample += "varchar("
				sample += sampleNumber(200)
				sample += ")"
				sample += sampleSpaces()
				sample += "select"
				sample += sampleSpaces()
				sample += "@"
				sample += name
				sample += sampleSpaces()
				sample += "="
				sample += sampleSpaces()
				sample += sampleHex(1337 * 1337)
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("declare")
				p.AddSpaces()
				p.AddLiteral("@")
				p.AddName(0)
				p.AddSpaces()
				p.AddLiteral("varchar(")
				p.AddNumber(1, 200)
				p.AddLiteral(")")
				p.AddSpaces()
				p.AddLiteral("select")
				p.AddSpaces()
				p.AddLiteral("@")
				p.AddName(0)
				p.AddSpaces()
				p.AddLiteral("=")
				p.AddSpaces()
				p.AddHex(1337 * 1337)
				return p
			},
		},
		{
			Form: "tz_offset",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += "tz_offset"
				sample += sampleSpaces()
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpacesOptional()
				p.AddLiteral("tz_offset")
				p.AddSpacesOptional()
				return p
			},
		},
		{
			Form: "sqlvuln",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += "sqlvuln"
				sample += sampleSpaces()
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpacesOptional()
				p.AddSQL()
				p.AddSpacesOptional()
				return p
			},
		},
		{
			Form:     "\"));waitfor delay '0:0:__TIME__'--",
			Abstract: true,
			Make: func() (sample string) {
				sample += "\"));waitfor"
				sample += sampleSpaces()
				sample += "delay"
				sample += sampleSpaces()
				sample += "'"
				sample += sampleNumber(24)
				sample += ":"
				sample += sampleNumber(60)
				sample += ":"
				sample += sampleNumber(60)
				sample += "'--"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("\"))")
				p.AddWaitfor()
				return p
			},
		},
		{
			Form: "||6",
			Make: func() (sample string) {
				sample += "||"
				sample += sampleNumber(1337)
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddOr()
				p.AddNumber(0, 1337)
				return p
			},
		},
		{
			Form: "or%201=1 --",
			Make: func() (sample string) {
				sample += sampleOr()
				sample += sampleHexSpaces()
				number := sampleNumber(1337)
				sample += number
				sample += "="
				sample += number
				sample += sampleSpaces()
				sample += "--"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddHexOr()
				p.AddNumber(0, 1337)
				p.AddLiteral("=")
				p.AddNumber(0, 1337)
				p.AddSpaces()
				p.AddLiteral("--")
				return p
			},
		},
		{
			Form: "%2A%28%7C%28objectclass%3D%2A%29%29",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += "%2A%28%7C%28objectclass%3D%2A%29%29"
				sample += sampleSpaces()
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpacesOptional()
				p.AddLiteral("%2A%28%7C%28objectclass%3D%2A%29%29")
				p.AddSpacesOptional()
				return p
			},
		},
		{
			Form: "or a=a",
			Make: func() (sample string) {
				sample += sampleOr()
				sample += sampleSpaces()
				name := sampleName()
				sample += name
				sample += "="
				sample += name
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddOr()
				p.AddSpaces()
				p.AddName(0)
				p.AddLiteral("=")
				p.AddName(0)
				return p
			},
		},
		{
			Form: ") union select * from information_schema.tables;",
			Make: func() (sample string) {
				sample += ")"
				sample += sampleSpaces()
				sample += "union"
				sample += sampleSpaces()
				sample += "select"
				sample += sampleSpaces()
				sample += "*"
				sample += sampleSpaces()
				sample += "form"
				sample += sampleSpaces()
				sample += "information_schema.tables;"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral(")")
				p.AddSpaces()
				p.AddLiteral("union")
				p.AddSpaces()
				p.AddLiteral("select")
				p.AddSpaces()
				p.AddLiteral("*")
				p.AddSpaces()
				p.AddLiteral("form")
				p.AddSpaces()
				p.AddLiteral("information_schema.tables;")
				return p
			},
		},
		{
			Form: "PRINT @@variable",
			Make: func() (sample string) {
				sample += "print"
				sample += sampleSpaces()
				sample += "@@"
				sample += sampleName()
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("print")
				p.AddSpaces()
				p.AddLiteral("@@")
				p.AddName(0)
				return p
			},
		},
		{
			Form: "or isNULL(1/0) /*",
			Make: func() (sample string) {
				sample += sampleOr()
				sample += sampleSpaces()
				sample += "isnull("
				sample += sampleNumber(1337)
				sample += "/0)"
				sample += sampleSpaces()
				sample += "/*"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddOr()
				p.AddLiteral("isnull(")
				p.AddSpacesOptional()
				p.AddNumber(0, 1337)
				p.AddSpacesOptional()
				p.AddLiteral("/")
				p.AddSpacesOptional()
				p.AddLiteral("0")
				p.AddSpacesOptional()
				p.AddLiteral(")")
				p.AddSpaces()
				p.AddLiteral("/*")
				return p
			},
		},
		{
			Form: "26 %",
			Make: func() (sample string) {
				sample += sampleNumber(1337)
				sample += sampleSpaces()
				sample += "%"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddNumber(0, 1337)
				p.AddSpaces()
				p.AddLiteral("%")
				return p
			},
		},
		{
			Form: "\" or \"a\"=\"a",
			Make: func() (sample string) {
				sample += "\""
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += "\""
				name := sampleName()
				sample += name
				sample += "\"=\""
				sample += name
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("\"")
				p.AddOr()
				p.AddLiteral("\"")
				p.AddName(0)
				p.AddLiteral("\"=\"")
				p.AddName(0)
				return p
			},
		},
		{
			Form: "(sqlvuln)",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += "(sqlvuln)"
				sample += sampleSpaces()
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpacesOptional()
				p.AddLiteral("(")
				p.AddSQL()
				p.AddLiteral(")")
				p.AddSpacesOptional()
				return p
			},
		},
		{
			Form: "x' AND members.email IS NULL; --",
			Make: func() (sample string) {
				sample += sampleName()
				sample += "'"
				sample += sampleSpaces()
				sample += sampleAnd()
				sample += sampleSpaces()
				sample += "members.email"
				sample += sampleSpaces()
				sample += "is"
				sample += sampleSpaces()
				sample += "null;"
				sample += sampleSpaces()
				sample += "--"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddName(0)
				p.AddLiteral("'")
				p.AddAnd()
				p.AddLiteral("members.email")
				p.AddSpaces()
				p.AddLiteral("is")
				p.AddSpaces()
				p.AddLiteral("null;")
				p.AddSpaces()
				p.AddLiteral("--")
				return p
			},
		},
		{
			Form: " or 1=1--",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += sampleOr()
				number := sampleNumber(1337)
				sample += number
				sample += "="
				sample += number
				sample += "--"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddOr()
				p.AddNumber(0, 1337)
				p.AddLiteral("=")
				p.AddNumber(0, 1337)
				p.AddLiteral("--")
				return p
			},
		},
		{
			Form:     " and 1=( if((load_file(char(110,46,101,120,11 ...",
			Abstract: true,
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += sampleAnd()
				sample += sampleSpaces()
				sample += sampleNumber(1337)
				sample += "=("
				sample += sampleSpaces()
				sample += "if((load_file(char("
				for i := 0; i < 7; i++ {
					sample += sampleNumber(256)
					sample += ","
				}
				sample += sampleNumber(256)
				sample += ")))))"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddAnd()
				p.AddNumber(0, 1337)
				p.AddLiteral("=(")
				p.AddSpaces()
				p.AddLiteral("if((load_file(char(")
				p.AddNumberList(256)
				p.AddLiteral(")))))")
				return p
			},
		},
		{
			Form:     "0x770061006900740066006F0072002000640065006C00 ...",
			Abstract: true,
			Make: func() (sample string) {
				sample += sampleHex(1337 * 1337)
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddHex(1337 * 1336)
				return p
			},
		},
		{
			Form: "%20'sleep%2050'",
			Make: func() (sample string) {
				sample += sampleHexSpaces()
				sample += "'sleep"
				sample += sampleHexSpaces()
				sample += sampleNumber(1337)
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddHexSpaces()
				p.AddLiteral("'sleep")
				p.AddHexSpaces()
				p.AddNumber(0, 1337)
				return p
			},
		},
		{
			Form: "as",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += "as"
				sample += sampleSpaces()
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpacesOptional()
				p.AddLiteral("as")
				p.AddSpacesOptional()
				return p
			},
		},
		{
			Form:     "1)) or pg_sleep(__TIME__)--",
			Abstract: true,
			Make: func() (sample string) {
				sample += sampleNumber(1337)
				sample += "))"
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += "pg_sleep("
				sample += sampleNumber(1337)
				sample += ")--"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddNumber(0, 1337)
				p.AddLiteral("))")
				p.AddOr()
				p.AddLiteral("pg_sleep(")
				p.AddSpacesOptional()
				p.AddNumber(1, 1337)
				p.AddSpacesOptional()
				p.AddLiteral(")--")
				return p
			},
		},
		{
			Form: "/**/or/**/1/**/=/**/1",
			Make: func() (sample string) {
				sampleComment := func() string {
					s := "/*"
					s += sampleName()
					s += "*/"
					return s
				}
				sample += sampleComment()
				sample += sampleOr()
				sample += sampleComment()
				number := sampleNumber(1337)
				sample += number
				sample += sampleComment()
				sample += "="
				sample += sampleComment()
				sample += number
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddComment()
				p.AddLiteral("or")
				p.AddComment()
				p.AddNumber(0, 1337)
				p.AddComment()
				p.AddLiteral("=")
				p.AddComment()
				p.AddNumber(0, 1337)
				return p
			},
		},
		{
			Form: " union all select @@version--",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += "union"
				sample += sampleSpaces()
				sample += "all"
				sample += sampleSpaces()
				sample += "select"
				sample += sampleSpaces()
				sample += "@@"
				sample += sampleName()
				sample += "--"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpaces()
				p.AddLiteral("union")
				p.AddSpaces()
				p.AddLiteral("all")
				p.AddSpaces()
				p.AddLiteral("select")
				p.AddSpaces()
				p.AddLiteral("@@")
				p.AddName(0)
				p.AddLiteral("--")
				return p
			},
		},
		{
			Form: ",@variable",
			Make: func() (sample string) {
				sample += ",@"
				sample += sampleName()
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral(",@")
				p.AddName(0)
				return p
			},
		},
		{
			Form: "(sqlattempt2)",
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpacesOptional()
				p.AddLiteral("(")
				p.AddSQL()
				p.AddLiteral(")")
				p.AddSpacesOptional()
				return p
			},
		},
		{
			Form: " or (EXISTS)",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += "(exists)"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddOr()
				p.AddLiteral("(exists)")
				return p
			},
		},
		{
			Form:     "t'exec master..xp_cmdshell 'nslookup www.googl ...",
			Abstract: true,
			Make: func() (sample string) {
				sample += sampleName()
				sample += "'exec"
				sample += sampleSpaces()
				sample += "master..xp_cmdshell"
				sample += sampleSpaces()
				sample += "'nslookup"
				sample += sampleSpaces()
				sample += sampleName()
				sample += "."
				sample += sampleName()
				sample += "."
				sample += sampleName()
				sample += "'"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddName(0)
				p.AddLiteral("'exec")
				p.AddSpaces()
				p.AddLiteral("master..xp_cmdshell")
				p.AddSpaces()
				p.AddLiteral("'nslookup")
				p.AddSpaces()
				p.AddName(1)
				p.AddLiteral(".")
				p.AddName(2)
				p.AddLiteral(".")
				p.AddName(3)
				p.AddLiteral("'")
				return p
			},
		},
		{
			Form: "%20$(sleep%2050)",
			Make: func() (sample string) {
				sample += sampleHexSpaces()
				sample += "$(sleep"
				sample += sampleHexSpaces()
				sample += sampleNumber(1337)
				sample += ")"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddHexSpaces()
				p.AddLiteral("$(sleep")
				p.AddHexSpaces()
				p.AddNumber(0, 1337)
				p.AddLiteral(")")
				return p
			},
		},
		{
			Form: "1 or benchmark(10000000,MD5(1))#",
			Make: func() (sample string) {
				sample += sampleNumber(1337)
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += sampleBenchmark()
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddNumber(0, 1337)
				p.AddOr()
				p.AddBenchmark()
				return p
			},
		},
		{
			Form: "%20or%20''='",
			Make: func() (sample string) {
				sample += sampleHexSpaces()
				sample += sampleOr()
				sample += sampleHexSpaces()
				sample += "''='"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddHexOr()
				p.AddLiteral("''='")
				return p
			},
		},
		{
			Form: "||UTL_HTTP.REQUEST",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += sampleOr()
				sample += "utl_http.request"
				sample += sampleSpaces()
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddOr()
				p.AddLiteral("utl_http.request")
				p.AddSpacesOptional()
				return p
			},
		},
		{
			Form:     " or pg_sleep(__TIME__)--",
			Abstract: true,
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += "pg_sleep("
				sample += sampleNumber(1337)
				sample += ")--"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddOr()
				p.AddLiteral("pg_sleep(")
				p.AddSpacesOptional()
				p.AddNumber(0, 1337)
				p.AddSpacesOptional()
				p.AddLiteral(")--")
				return p
			},
		},
		{
			Form: "hi' or 'x'='x';",
			Make: func() (sample string) {
				sample += sampleName()
				sample += "'"
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += "'"
				name := sampleName()
				sample += name
				sample += "'='"
				sample += name
				sample += "';"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddName(0)
				p.AddLiteral("'")
				p.AddOr()
				p.AddLiteral("'")
				p.AddName(1)
				p.AddLiteral("'='")
				p.AddName(1)
				p.AddLiteral("';")
				return p
			},
		},
		{
			Form:     "\") or sleep(__TIME__)=\"",
			Abstract: true,
			Make: func() (sample string) {
				sample += "\")"
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += "sleep("
				sample += sampleNumber(1337)
				sample += ")=\""
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("\")")
				p.AddOr()
				p.AddLiteral("sleep(")
				p.AddSpacesOptional()
				p.AddNumber(0, 1337)
				p.AddSpacesOptional()
				p.AddLiteral(")=\"")
				return p
			},
		},
		{
			Form: " or 'whatever' in ('whatever')",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += "'"
				name := sampleName()
				sample += name
				sample += "'"
				sample += sampleSpaces()
				sample += "in"
				sample += sampleSpaces()
				sample += "('"
				sample += name
				sample += "')"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddOr()
				p.AddLiteral("'")
				p.AddName(0)
				p.AddLiteral("'")
				p.AddSpaces()
				p.AddLiteral("in")
				p.AddSpaces()
				p.AddLiteral("('")
				p.AddName(0)
				p.AddLiteral("')")
				return p
			},
		},
		{
			Form:     "; begin declare @var varchar(8000) set @var=' ...",
			Abstract: true,
			Make: func() (sample string) {
				sample += ";"
				sample += sampleSpaces()
				sample += "begin"
				sample += sampleSpaces()
				sample += "declare"
				sample += sampleSpaces()
				sample += "@"
				name := sampleName()
				sample += name
				sample += sampleSpaces()
				sample += "varchar("
				sample += sampleNumber(8000)
				sample += ")"
				sample += sampleSpaces()
				sample += "set"
				sample += sampleSpaces()
				sample += "@"
				sample += name
				sample += "='"
				sample += sampleName()
				sample += "'"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral(";")
				p.AddSpaces()
				p.AddLiteral("begin")
				p.AddSpaces()
				p.AddLiteral("declare")
				p.AddSpaces()
				p.AddLiteral("@")
				p.AddName(0)
				p.AddSpaces()
				p.AddLiteral("varchar(")
				p.AddNumber(1, 8000)
				p.AddLiteral(")")
				p.AddSpaces()
				p.AddLiteral("set")
				p.AddSpaces()
				p.AddLiteral("@")
				p.AddName(0)
				p.AddLiteral("='")
				p.AddName(2)
				p.AddLiteral("'")
				return p
			},
		},
		{
			Form: " union select 1,load_file('/etc/passwd'),1,1,1;",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += "union"
				sample += sampleSpaces()
				sample += "select"
				sample += sampleSpaces()
				sample += sampleNumber(1337)
				sample += ",load_file('/etc/passwd')"
				for i := 0; i < 3; i++ {
					sample += ","
					sample += sampleNumber(1337)
				}
				sample += ";"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpaces()
				p.AddLiteral("union")
				p.AddSpaces()
				p.AddLiteral("select")
				p.AddSpaces()
				p.AddNumber(0, 1337)
				p.AddLiteral(",load_file('/etc/passwd'),1,1,1;")
				return p
			},
		},
		{
			Form:     "0x77616974666F722064656C61792027303A303A313027 ...",
			Abstract: true,
			Make: func() (sample string) {
				sample += sampleHex(1337 * 1337)
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddHex(1337 * 1337)
				return p
			},
		},
		{
			Form: "exec(@s)",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += "exec(@"
				sample += sampleName()
				sample += ")"
				sample += sampleSpaces()
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpaces()
				p.AddLiteral("exec(@")
				p.AddName(0)
				p.AddLiteral(")")
				p.AddSpacesOptional()
				return p
			},
		},
		{
			Form:     ") or pg_sleep(__TIME__)--",
			Abstract: true,
			Make: func() (sample string) {
				sample += ")"
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += "pg_sleep("
				sample += sampleNumber(1337)
				sample += ")--"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral(")")
				p.AddOr()
				p.AddLiteral("pg_sleep(")
				p.AddNumber(0, 1337)
				p.AddLiteral(")--")
				return p
			},
		},
		{
			Form: " union select",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += "union"
				sample += sampleSpaces()
				sample += "select"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpaces()
				p.AddLiteral("union")
				p.AddSpaces()
				p.AddLiteral("select")
				return p
			},
		},
		{
			Form:     " or sleep(__TIME__)#",
			Abstract: true,
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += "sleep("
				sample += sampleNumber(1337)
				sample += ")#"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddOr()
				p.AddLiteral("sleep(")
				p.AddSpacesOptional()
				p.AddNumber(0, 1337)
				p.AddSpacesOptional()
				p.AddLiteral(")#")
				return p
			},
		},
		{
			Form: " select * from information_schema.tables--",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += "select"
				sample += sampleSpaces()
				sample += "*"
				sample += sampleSpaces()
				sample += "from"
				sample += sampleSpaces()
				sample += "information_schema.tables--"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpaces()
				p.AddLiteral("select")
				p.AddSpaces()
				p.AddLiteral("*")
				p.AddSpaces()
				p.AddLiteral("from")
				p.AddSpaces()
				p.AddLiteral("information_schema.tables--")
				return p
			},
		},
		{
			Form: "a' or 1=1--",
			Make: func() (sample string) {
				sample += sampleName()
				sample += "'"
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				number := sampleNumber(1337)
				sample += number
				sample += "="
				sample += number
				sample += "--"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddName(0)
				p.AddLiteral("'")
				p.AddOr()
				p.AddNumber(1, 1337)
				p.AddLiteral("=")
				p.AddNumber(1, 1337)
				p.AddLiteral("--")
				return p
			},
		},
		{
			Form: "a' or 'a' = 'a",
			Make: func() (sample string) {
				sample += sampleName()
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += "'"
				name := sampleName()
				sample += name
				sample += "'"
				sample += sampleSpaces()
				sample += "="
				sample += sampleSpaces()
				sample += "'"
				sample += name
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddName(0)
				p.AddSpaces()
				p.AddOr()
				p.AddLiteral("'")
				p.AddName(1)
				p.AddLiteral("'")
				p.AddSpaces()
				p.AddLiteral("=")
				p.AddSpaces()
				p.AddLiteral("'")
				p.AddName(1)
				return p
			},
		},
		{
			Form: "declare @s varchar(22) select @s =",
			Make: func() (sample string) {
				sample += "declare"
				sample += sampleSpaces()
				sample += "@"
				name := sampleName()
				sample += name
				sample += sampleSpaces()
				sample += "varchar("
				sample += sampleNumber(22)
				sample += ")"
				sample += sampleSpaces()
				sample += "select"
				sample += sampleSpaces()
				sample += "@"
				sample += name
				sample += sampleSpaces()
				sample += "="
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("declare")
				p.AddSpaces()
				p.AddLiteral("@")
				p.AddName(0)
				p.AddSpaces()
				p.AddLiteral("varchar(")
				p.AddNumber(1, 22)
				p.AddLiteral(")")
				p.AddSpaces()
				p.AddLiteral("select")
				p.AddSpaces()
				p.AddLiteral("@")
				p.AddName(0)
				p.AddSpaces()
				p.AddLiteral("=")
				return p
			},
		},
		{
			Form: " or 2 between 1 and 3",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += sampleNumber(1337)
				sample += sampleSpaces()
				sample += "between"
				sample += sampleSpaces()
				sample += sampleNumber(1337)
				sample += sampleSpaces()
				sample += "and"
				sample += sampleSpaces()
				sample += sampleNumber(1337)
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddOr()
				p.AddNumber(0, 1337)
				p.AddSpaces()
				p.AddLiteral("between")
				p.AddSpaces()
				p.AddNumber(1, 1337)
				p.AddSpaces()
				p.AddLiteral("and")
				p.AddSpaces()
				p.AddNumber(2, 1337)
				return p
			},
		},
		{
			Form: " or a=a--",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				name := sampleName()
				sample += name
				sample += "="
				sample += name
				sample += "--"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddOr()
				p.AddName(0)
				p.AddLiteral("=")
				p.AddName(0)
				p.AddLiteral("--")
				return p
			},
		},
		{
			Form: " or '1'='1",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += "'"
				number := sampleNumber(1337)
				sample += number
				sample += "'='"
				sample += number
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddOr()
				p.AddLiteral("'")
				p.AddNumber(0, 1337)
				p.AddLiteral("'='")
				p.AddNumber(0, 1337)
				return p
			},
		},
		{
			Form: "|",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += "|"
				sample += sampleSpaces()
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpacesOptional()
				p.AddLiteral("|")
				p.AddSpacesOptional()
				return p
			},
		},
		{
			Form:     " or sleep(__TIME__)='",
			Abstract: true,
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += "sleep("
				sample += sampleNumber(1337)
				sample += ")='"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddOr()
				p.AddLiteral("sleep(")
				p.AddSpacesOptional()
				p.AddNumber(0, 1337)
				p.AddSpacesOptional()
				p.AddLiteral(")='")
				return p
			},
		},
		{
			Form: " or 1 --'",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += sampleNumber(1337)
				sample += sampleSpaces()
				sample += "--'"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddOr()
				p.AddNumber(0, 1337)
				p.AddSpaces()
				p.AddLiteral("--'")
				return p
			},
		},
		{
			Form: "or 0=0 #\"",
			Make: func() (sample string) {
				sample += sampleOr()
				sample += sampleSpaces()
				number := sampleNumber(1337)
				sample += number
				sample += "="
				sample += number
				sample += sampleSpaces()
				sample += "#\""
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddOr()
				p.AddNumber(0, 1337)
				p.AddLiteral("=")
				p.AddNumber(0, 1337)
				p.AddSpaces()
				p.AddLiteral("#\"")
				return p
			},
		},
		{
			Form: "having",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += "having"
				sample += sampleSpaces()
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpacesOptional()
				p.AddLiteral("having")
				p.AddSpacesOptional()
				return p
			},
		},
		{
			Form: "a'",
			Make: func() (sample string) {
				sample += sampleName()
				sample += "'"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddName(0)
				p.AddLiteral("'")
				return p
			},
		},
		{
			Form: "\" or isNULL(1/0) /*",
			Make: func() (sample string) {
				sample += "\""
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += "isnull("
				sample += sampleNumber(1337)
				sample += "/0)"
				sample += sampleSpaces()
				sample += "/*"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("\"")
				p.AddOr()
				p.AddLiteral("isnull(")
				p.AddSpacesOptional()
				p.AddNumber(0, 1337)
				p.AddSpacesOptional()
				p.AddLiteral("/")
				p.AddSpacesOptional()
				p.AddLiteral("0")
				p.AddSpacesOptional()
				p.AddLiteral(")")
				p.AddSpaces()
				p.AddLiteral("/*")
				return p
			},
		},
		{
			Form:     "declare @s varchar (8000) select @s = 0x73656c ...",
			Abstract: true,
			Make: func() (sample string) {
				sample += "declare"
				sample += sampleSpaces()
				sample += "@"
				name := sampleName()
				sample += name
				sample += sampleSpaces()
				sample += "varchar"
				sample += sampleSpaces()
				sample += "("
				sample += sampleNumber(8000)
				sample += ")"
				sample += sampleSpaces()
				sample += "select"
				sample += sampleSpaces()
				sample += "@"
				sample += name
				sample += sampleSpaces()
				sample += "="
				sample += sampleSpaces()
				sample += sampleHex(1337 * 1337)
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("declare")
				p.AddSpaces()
				p.AddLiteral("@")
				p.AddName(0)
				p.AddSpaces()
				p.AddLiteral("varchar")
				p.AddSpaces()
				p.AddLiteral("(")
				p.AddNumber(1, 1337)
				p.AddLiteral(")")
				p.AddSpaces()
				p.AddLiteral("select")
				p.AddSpaces()
				p.AddLiteral("@")
				p.AddName(0)
				p.AddSpaces()
				p.AddLiteral("=")
				p.AddSpaces()
				p.AddHex(1337 * 1337)
				return p
			},
		},
		{
			Form: "â or 1=1 --",
			Make: func() (sample string) {
				sample += sampleName()
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				number := sampleNumber(1337)
				sample += number
				sample += "="
				sample += number
				sample += sampleSpaces()
				sample += "--"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddName(0)
				p.AddOr()
				p.AddNumber(0, 1337)
				p.AddLiteral("=")
				p.AddNumber(0, 1337)
				p.AddSpaces()
				p.AddLiteral("--")
				return p
			},
		},
		{
			Form: "char%4039%41%2b%40SELECT",
			Make: func() (sample string) {
				sample += "char%40"
				sample += sampleNumber(256)
				sample += "%41%2b%40select"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("char%40")
				p.AddNumber(0, 256)
				p.AddLiteral("%41%2b%40select")
				return p
			},
		},
		{
			Form: "order by",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += "order"
				sample += sampleSpaces()
				sample += "by"
				sample += sampleSpaces()
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpacesOptional()
				p.AddLiteral("order")
				p.AddSpaces()
				p.AddLiteral("by")
				p.AddSpacesOptional()
				return p
			},
		},
		{
			Form: "bfilename",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += "bfilename"
				sample += sampleSpaces()
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpacesOptional()
				p.AddLiteral("bfilename")
				p.AddSpacesOptional()
				return p
			},
		},
		{
			Form: " having 1=1--",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += "having"
				sample += sampleSpaces()
				number := sampleNumber(1337)
				sample += number
				sample += "="
				sample += number
				sample += "--"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpaces()
				p.AddLiteral("having")
				p.AddSpaces()
				p.AddNumber(0, 1337)
				p.AddLiteral("=")
				p.AddNumber(0, 1337)
				p.AddLiteral("--")
				return p
			},
		},
		{
			Form: ") or benchmark(10000000,MD5(1))#",
			Make: func() (sample string) {
				sample += ")"
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += sampleBenchmark()
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral(")")
				p.AddOr()
				p.AddBenchmark()
				return p
			},
		},
		{
			Form: " or username like char(37);",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += sampleName()
				sample += sampleSpaces()
				sample += "like"
				sample += sampleSpaces()
				sample += "char("
				sample += sampleNumber(256)
				sample += ");"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddOr()
				p.AddName(0)
				p.AddSpaces()
				p.AddLiteral("like")
				p.AddSpaces()
				p.AddLiteral("char(")
				p.AddNumber(1, 256)
				p.AddLiteral(");")
				return p
			},
		},
		{
			Form:     ";waitfor delay '0:0:__TIME__'--",
			Abstract: true,
			Make: func() (sample string) {
				sample += ";waitfor"
				sample += sampleSpaces()
				sample += "delay"
				sample += sampleSpaces()
				sample += "'"
				sample += sampleNumber(24)
				sample += ":"
				sample += sampleNumber(60)
				sample += ":"
				sample += sampleNumber(60)
				sample += "'--"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddWaitfor()
				return p
			},
		},
		{
			Form: "\" or 1=1--",
			Make: func() (sample string) {
				sample += "\""
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				number := sampleNumber(1337)
				sample += number
				sample += "="
				sample += number
				sample += "--"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("\"")
				p.AddOr()
				p.AddNumber(0, 1337)
				p.AddLiteral("=")
				p.AddNumber(0, 1337)
				p.AddLiteral("--")
				return p
			},
		},
		{
			Form: "x' AND userid IS NULL; --",
			Make: func() (sample string) {
				sample += sampleName()
				sample += "'"
				sample += sampleSpaces()
				sample += sampleAnd()
				sample += sampleSpaces()
				sample += sampleName()
				sample += sampleSpaces()
				sample += "is"
				sample += sampleSpaces()
				sample += "null;"
				sample += sampleSpaces()
				sample += "--"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddName(0)
				p.AddLiteral("'")
				p.AddAnd()
				p.AddName(1)
				p.AddSpaces()
				p.AddLiteral("is")
				p.AddSpaces()
				p.AddLiteral("null;")
				p.AddSpaces()
				p.AddLiteral("--")
				return p
			},
		},
		{
			Form: "*/*",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += "*"
				sample += sampleSpaces()
				sample += "/*"
				sample += sampleSpaces()
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpacesOptional()
				p.AddLiteral("*")
				p.AddSpacesOptional()
				p.AddLiteral("/*")
				p.AddSpaces()
				return p
			},
		},
		{
			Form: " or 'text' > 't'",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += "'"
				short := sampleName()
				long := short + sampleName()
				sample += long
				sample += "'"
				sample += sampleSpaces()
				sample += ">"
				sample += sampleSpaces()
				sample += "'"
				sample += short
				sample += "'"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddOr()
				p.AddLiteral("'")
				p.AddName(0)
				p.AddLiteral("'")
				p.AddSpaces()
				p.AddLiteral(">")
				p.AddSpaces()
				p.AddLiteral("'")
				p.AddName(1)
				p.AddLiteral("'")
				return p
			},
		},
		{
			Form: " (select top 1",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += "(select"
				sample += sampleSpaces()
				sample += "top"
				sample += sampleSpaces()
				sample += sampleNumber(1337)
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpaces()
				p.AddLiteral("(select")
				p.AddSpaces()
				p.AddLiteral("top")
				p.AddSpaces()
				p.AddNumber(0, 1337)
				return p
			},
		},
		{
			Form: " or benchmark(10000000,MD5(1))#",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += sampleBenchmark()
				sample += "#"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddOr()
				p.AddBenchmark()
				return p
			},
		},
		{
			Form:     "\");waitfor delay '0:0:__TIME__'--",
			Abstract: true,
			Make: func() (sample string) {
				sample += "\");waitfor"
				sample += sampleSpaces()
				sample += "delay"
				sample += sampleSpaces()
				sample += "'"
				sample += sampleNumber(24)
				sample += ":"
				sample += sampleNumber(60)
				sample += ":"
				sample += sampleNumber(60)
				sample += "'--"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("\")")
				p.AddWaitfor()
				return p
			},
		},
		{
			Form: "a' or 3=3--",
			Make: func() (sample string) {
				sample += sampleName()
				sample += "'"
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				number := sampleNumber(1337)
				sample += number
				sample += "="
				sample += number
				sample += "--"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddName(0)
				p.AddLiteral("'")
				p.AddOr()
				p.AddNumber(1, 1337)
				p.AddLiteral("=")
				p.AddNumber(1, 1337)
				p.AddLiteral("--")
				return p
			},
		},
		{
			Form: " -- &password=",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += "--"
				sample += sampleSpaces()
				sample += "&"
				sample += sampleName()
				sample += "="
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpaces()
				p.AddLiteral("--")
				p.AddSpaces()
				p.AddLiteral("&")
				p.AddName(0)
				p.AddLiteral("=")
				return p
			},
		},
		{
			Form: " group by userid having 1=1--",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += "group"
				sample += sampleSpaces()
				sample += "by"
				sample += sampleSpaces()
				sample += sampleName()
				sample += sampleSpaces()
				sample += "having"
				sample += sampleSpaces()
				number := sampleNumber(1337)
				sample += number
				sample += "="
				sample += number
				sample += "--"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpaces()
				p.AddLiteral("group")
				p.AddSpaces()
				p.AddLiteral("by")
				p.AddSpaces()
				p.AddName(0)
				p.AddSpaces()
				p.AddLiteral("having")
				p.AddSpaces()
				p.AddNumber(1, 1337)
				p.AddLiteral("=")
				p.AddNumber(1, 1337)
				p.AddLiteral("--")
				return p
			},
		},
		{
			Form: " or ''='",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += "''='"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddOr()
				p.AddLiteral("''='")
				return p
			},
		},
		{
			Form: "; exec master..xp_cmdshell",
			Make: func() (sample string) {
				sample += ";"
				sample += sampleSpaces()
				sample += "exec"
				sample += sampleSpaces()
				sample += "master..xp_cmdshell"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral(";")
				p.AddSpaces()
				p.AddLiteral("exec")
				p.AddSpaces()
				p.AddLiteral("master..xp_cmdshell")
				return p
			},
		},
		{
			Form: "%20or%20x=x",
			Make: func() (sample string) {
				sample += sampleHexSpaces()
				sample += sampleOr()
				sample += sampleHexSpaces()
				name := sampleName()
				sample += name
				sample += "="
				sample += name
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddHexOr()
				p.AddName(0)
				p.AddLiteral("=")
				p.AddName(0)
				return p
			},
		},
		{
			Form: "select",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += "select"
				sample += sampleSpaces()
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpacesOptional()
				p.AddLiteral("select")
				p.AddSpacesOptional()
				return p
			},
		},
		{
			Form:     "\")) or sleep(__TIME__)=\"",
			Abstract: true,
			Make: func() (sample string) {
				sample += "\"))"
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += "sleep("
				sample += sampleNumber(1337)
				sample += ")=\""
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("\"))")
				p.AddOr()
				p.AddLiteral("sleep(")
				p.AddSpacesOptional()
				p.AddNumber(0, 1337)
				p.AddSpacesOptional()
				p.AddLiteral(")=\"")
				return p
			},
		},
		{
			Form:     "0x730065006c0065006300740020004000400076006500 ...",
			Abstract: true,
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += sampleHex(1337 * 1337)
				sample += sampleSpaces()
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpacesOptional()
				p.AddHex(1337 * 1337)
				p.AddSpacesOptional()
				return p
			},
		},
		{
			Form: "hi' or 1=1 --",
			Make: func() (sample string) {
				sample += sampleName()
				sample += "'"
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				number := sampleNumber(1337)
				sample += number
				sample += "="
				sample += number
				sample += sampleSpaces()
				sample += "--"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddName(0)
				p.AddLiteral("'")
				p.AddOr()
				p.AddNumber(1, 1337)
				p.AddLiteral("=")
				p.AddNumber(1, 1337)
				p.AddSpaces()
				p.AddLiteral("--")
				return p
			},
		},
		{
			Form:     "\") or pg_sleep(__TIME__)--",
			Abstract: true,
			Make: func() (sample string) {
				sample += "\")"
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += "pg_sleep("
				sample += sampleNumber(1337)
				sample += ")--"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("\")")
				p.AddOr()
				p.AddLiteral("pg_sleep(")
				p.AddSpacesOptional()
				p.AddNumber(0, 1337)
				p.AddLiteral(")--")
				return p
			},
		},
		{
			Form: "%20or%20'x'='x",
			Make: func() (sample string) {
				sample += sampleHexSpaces()
				sample += sampleOr()
				sample += sampleHexSpaces()
				sample += "'"
				name := sampleName()
				sample += name
				sample += "'='"
				sample += name
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddHexOr()
				p.AddLiteral("'")
				p.AddName(0)
				p.AddLiteral("'='")
				p.AddName(0)
				return p
			},
		},
		{
			Form: " or 'something' = 'some'+'thing'",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += "'"
				name := sampleName()
				sample += name
				sample += "'"
				sample += sampleSpaces()
				sample += "="
				sample += sampleSpaces()
				sample += "'"
				for _, v := range name {
					sample += string(v)
					if rnd.Intn(3) == 0 {
						sample += "'+'"
					}
				}
				sample += "'"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddOr()
				p.AddLiteral("'")
				p.AddName(0)
				p.AddLiteral("'")
				p.AddSpaces()
				p.AddLiteral("=")
				p.AddSpaces()
				p.AddParts(PartTypeObfuscated, func(p *Parts) {
					p.AddName(0)
				})
				return p
			},
		},
		{
			Form: "exec sp",
			Make: func() (sample string) {
				sample += "exec"
				sample += sampleSpaces()
				sample += "sp"
				sample += sampleSpaces()
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpacesOptional()
				p.AddLiteral("exec")
				p.AddSpaces()
				p.AddLiteral("sp")
				p.AddSpacesOptional()
				return p
			},
		},
		{
			Form: "29 %",
			Make: func() (sample string) {
				sample += sampleNumber(1337)
				sample += sampleSpaces()
				sample += "%"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddNumber(0, 1337)
				p.AddSpaces()
				p.AddLiteral("%")
				return p
			},
		},
		{
			Form: "(",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += "("
				sample += sampleSpaces()
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpacesOptional()
				p.AddLiteral("(")
				p.AddSpacesOptional()
				return p
			},
		},
		{
			Form: "Ã½ or 1=1 --",
			Make: func() (sample string) {
				sample += sampleName()
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				number := sampleNumber(1337)
				sample += number
				sample += "="
				sample += number
				sample += sampleSpaces()
				sample += "--"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddName(0)
				p.AddOr()
				p.AddNumber(1, 1337)
				p.AddLiteral("=")
				p.AddNumber(1, 1337)
				p.AddSpaces()
				p.AddLiteral("--")
				return p
			},
		},
		{
			Form:     "1 or pg_sleep(__TIME__)--",
			Abstract: true,
			Make: func() (sample string) {
				sample += sampleNumber(1337)
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += "pg_sleep("
				sample += sampleNumber(1337)
				sample += ")--"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddNumber(0, 1337)
				p.AddOr()
				p.AddLiteral("pg_sleep(")
				p.AddSpacesOptional()
				p.AddNumber(1, 1337)
				p.AddSpacesOptional()
				p.AddLiteral(")--")
				return p
			},
		},
		{
			Form: "0 or 1=1",
			Make: func() (sample string) {
				sample += sampleNumber(1337)
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				number := sampleNumber(1337)
				sample += number
				sample += "="
				sample += number
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddNumber(0, 1337)
				p.AddOr()
				p.AddNumber(1, 1337)
				p.AddLiteral("=")
				p.AddNumber(1, 1337)
				return p
			},
		},
		{
			Form: ") or (a=a",
			Make: func() (sample string) {
				sample += ")"
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += "("
				name := sampleName()
				sample += name
				sample += "="
				sample += name
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral(")")
				p.AddOr()
				p.AddLiteral("(")
				p.AddName(0)
				p.AddLiteral("=")
				p.AddName(0)
				return p
			},
		},
		{
			Form: "uni/**/on sel/**/ect",
			Make: func() (sample string) {
				form := "union"
				form += sampleSpaces()
				form += "select"
				for _, v := range form {
					sample += string(v)
					if rnd.Intn(3) == 0 {
						sample += "/**/"
					}
				}
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddParts(PartTypeObfuscatedWithComments, func(p *Parts) {
					p.AddLiteral("union")
					p.AddSpaces()
					p.AddLiteral("select")
				})
				return p
			},
		},
		{
			Form: "replace",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += "replace"
				sample += sampleSpaces()
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpacesOptional()
				p.AddLiteral("replace")
				p.AddSpacesOptional()
				return p
			},
		},
		{
			Form: "%27%20or%201=1",
			Make: func() (sample string) {
				sample += "%27"
				sample += sampleHexSpaces()
				sample += sampleOr()
				sample += sampleHexSpaces()
				number := sampleNumber(1337)
				sample += number
				sample += "="
				sample += number
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("%27")
				p.AddHexOr()
				p.AddNumber(0, 1337)
				p.AddLiteral("=")
				p.AddNumber(0, 1337)
				return p
			},
		},
		{
			Form:     ")) or pg_sleep(__TIME__)--",
			Abstract: true,
			Make: func() (sample string) {
				sample += "))"
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += "pg_sleep("
				sample += sampleNumber(1337)
				sample += ")--"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("))")
				p.AddOr()
				p.AddLiteral("pg_sleep(")
				p.AddSpacesOptional()
				p.AddNumber(0, 1337)
				p.AddSpacesOptional()
				p.AddLiteral(")--")
				return p
			},
		},
		{
			Form: "%7C",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += "%7C"
				sample += sampleSpaces()
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpacesOptional()
				p.AddLiteral("%7C")
				p.AddSpacesOptional()
				return p
			},
		},
		{
			Form: "x' AND 1=(SELECT COUNT(*) FROM tabname); --",
			Make: func() (sample string) {
				sample += sampleName()
				sample += "'"
				sample += sampleSpaces()
				sample += sampleAnd()
				sample += sampleSpaces()
				sample += "1=(select"
				sample += sampleSpaces()
				sample += "count(*)"
				sample += sampleSpaces()
				sample += "from"
				sample += sampleSpaces()
				sample += "tabname);"
				sample += sampleSpaces()
				sample += "--"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("'")
				p.AddAnd()
				p.AddLiteral("1=(select")
				p.AddSpaces()
				p.AddLiteral("count(*)")
				p.AddSpaces()
				p.AddLiteral("from")
				p.AddSpaces()
				p.AddName(0)
				p.AddLiteral(");")
				p.AddSpaces()
				p.AddLiteral("--")
				return p
			},
		},
		{
			Form: "&apos;%20OR",
			Make: func() (sample string) {
				sample += "&apos;"
				sample += sampleHexSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("&apos;")
				p.AddHexOr()
				return p
			},
		},
		{
			Form: "; or '1'='1'",
			Make: func() (sample string) {
				sample += ";"
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += "'"
				number := sampleNumber(1337)
				sample += number
				sample += "'='"
				sample += number
				sample += "'"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral(";")
				p.AddOr()
				p.AddLiteral("'")
				p.AddNumber(0, 1337)
				p.AddLiteral("'='")
				p.AddNumber(0, 1337)
				p.AddLiteral("'")
				return p
			},
		},
		{
			Form:     "declare @q nvarchar (200) select @q = 0x770061 ...",
			Abstract: true,
			Make: func() (sample string) {
				sample += "declare"
				sample += sampleSpaces()
				sample += "@"
				name := sampleName()
				sample += name
				sample += sampleSpaces()
				sample += "nvarchar"
				sample += sampleSpaces()
				sample += "("
				sample += sampleNumber(200)
				sample += ")"
				sample += sampleSpaces()
				sample += "select"
				sample += sampleSpaces()
				sample += "@"
				sample += name
				sample += sampleSpaces()
				sample += "="
				sample += sampleSpaces()
				sample += sampleHex(1337 * 1337)
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("declare")
				p.AddSpaces()
				p.AddLiteral("@")
				p.AddName(0)
				p.AddSpaces()
				p.AddLiteral("nvarchar")
				p.AddSpaces()
				p.AddLiteral("(")
				p.AddNumber(1, 200)
				p.AddLiteral(")")
				p.AddSpaces()
				p.AddLiteral("select")
				p.AddSpaces()
				p.AddLiteral("@")
				p.AddName(0)
				p.AddSpaces()
				p.AddLiteral("=")
				p.AddSpaces()
				p.AddHex(1337 * 1337)
				return p
			},
		},
		{
			Form: "1 or 1=1",
			Make: func() (sample string) {
				sample += sampleNumber(1337)
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				number := sampleNumber(1337)
				sample += number
				sample += "="
				sample += number
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddNumber(0, 1337)
				p.AddOr()
				p.AddNumber(1, 1337)
				p.AddLiteral("=")
				p.AddNumber(1, 1337)
				return p
			},
		},
		{
			Form: "; exec ('sel' + 'ect us' + 'er')",
			Make: func() (sample string) {
				sample += ";"
				sample += sampleSpaces()
				sample += "exec"
				sample += sampleSpaces()
				sample += "('"
				form := "select " + sampleName()
				for _, v := range form {
					sample += string(v)
					if rnd.Intn(3) == 0 {
						sample += "' + '"
					}
				}
				sample += "')"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral(";")
				p.AddSpaces()
				p.AddLiteral("exec")
				p.AddSpaces()
				p.AddLiteral("(")
				p.AddParts(PartTypeObfuscated, func(p *Parts) {
					p.AddLiteral("select")
					p.AddSpaces()
					p.AddName(0)
				})
				p.AddLiteral(")")
				return p
			},
		},
		{
			Form: "23 OR 1=1",
			Make: func() (sample string) {
				sample += sampleNumber(1337)
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				number := sampleNumber(1337)
				sample += number
				sample += "="
				sample += number
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddNumber(0, 1337)
				p.AddOr()
				p.AddNumber(1, 1337)
				p.AddLiteral("=")
				p.AddNumber(1, 1337)
				return p
			},
		},
		{
			Form: "/",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += "/"
				sample += sampleSpaces()
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpacesOptional()
				p.AddLiteral("/")
				p.AddSpacesOptional()
				return p
			},
		},
		{
			Form: "anything' OR 'x'='x",
			Make: func() (sample string) {
				sample += sampleName()
				sample += "'"
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += "'"
				name := sampleName()
				sample += name
				sample += "'='"
				sample += name
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddName(0)
				p.AddLiteral("'")
				p.AddOr()
				p.AddLiteral("'")
				p.AddName(1)
				p.AddLiteral("'='")
				p.AddName(1)
				return p
			},
		},
		{
			Form: "declare @q nvarchar (4000) select @q =",
			Make: func() (sample string) {
				sample += "declare"
				sample += sampleSpaces()
				sample += "@"
				name := sampleName()
				sample += name
				sample += sampleSpaces()
				sample += "nvarchar"
				sample += sampleSpaces()
				sample += "("
				sample += sampleNumber(4000)
				sample += ")"
				sample += sampleSpaces()
				sample += "select"
				sample += sampleSpaces()
				sample += "@"
				sample += name
				sample += sampleSpaces()
				sample += "="
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("declare")
				p.AddSpaces()
				p.AddLiteral("@")
				p.AddName(0)
				p.AddSpaces()
				p.AddLiteral("nvarchar")
				p.AddSpaces()
				p.AddLiteral("(")
				p.AddNumber(1, 4000)
				p.AddLiteral(")")
				p.AddSpaces()
				p.AddLiteral("select")
				p.AddSpaces()
				p.AddLiteral("@")
				p.AddName(0)
				p.AddSpaces()
				p.AddLiteral("=")
				return p
			},
		},
		{
			Form: "or 0=0 --",
			Make: func() (sample string) {
				sample += sampleOr()
				sample += sampleSpaces()
				number := sampleNumber(1337)
				sample += number
				sample += "="
				sample += number
				sample += sampleSpaces()
				sample += "--"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddOr()
				p.AddNumber(0, 1337)
				p.AddLiteral("=")
				p.AddNumber(0, 1337)
				p.AddSpaces()
				p.AddLiteral("--")
				return p
			},
		},
		{
			Form: "desc",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += "desc"
				sample += sampleSpaces()
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpacesOptional()
				p.AddLiteral("desc")
				p.AddSpacesOptional()
				return p
			},
		},
		{
			Form: "||'6",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += "||'6"
				sample += sampleSpaces()
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpacesOptional()
				p.AddLiteral("||'6")
				p.AddSpacesOptional()
				return p
			},
		},
		{
			Form: ")",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += ")"
				sample += sampleSpaces()
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpacesOptional()
				p.AddLiteral(")")
				p.AddSpacesOptional()
				return p
			},
		},
		{
			Form:     "1)) or sleep(__TIME__)#",
			Abstract: true,
			Make: func() (sample string) {
				sample += sampleNumber(1337)
				sample += "))"
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += "sleep("
				sample += sampleNumber(1337)
				sample += ")#"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddNumber(0, 1337)
				p.AddLiteral("))")
				p.AddOr()
				p.AddLiteral("sleep(")
				p.AddSpacesOptional()
				p.AddNumber(1, 1337)
				p.AddSpacesOptional()
				p.AddLiteral(")#")
				return p
			},
		},
		{
			Form: "or 0=0 #",
			Make: func() (sample string) {
				sample += sampleOr()
				sample += sampleSpaces()
				number := sampleNumber(1337)
				sample += number
				sample += "="
				sample += number
				sample += sampleSpaces()
				sample += "#"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddOr()
				p.AddNumber(0, 1337)
				p.AddLiteral("=")
				p.AddNumber(0, 1337)
				p.AddSpaces()
				p.AddLiteral("#")
				return p
			},
		},
		{
			Form:     " select name from syscolumns where id = (sele ...",
			Abstract: true,
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += "select"
				sample += sampleSpaces()
				sample += sampleName()
				sample += sampleSpaces()
				sample += "from"
				sample += sampleSpaces()
				sample += sampleName()
				sample += sampleSpaces()
				sample += "where"
				sample += sampleSpaces()
				sample += sampleName()
				sample += sampleSpaces()
				sample += "="
				sample += sampleSpaces()
				sample += "(select "
				sample += sampleNumber(1337)
				sample += ")"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpaces()
				p.AddLiteral("select")
				p.AddSpaces()
				p.AddName(0)
				p.AddSpaces()
				p.AddLiteral("from")
				p.AddSpaces()
				p.AddName(1)
				p.AddSpaces()
				p.AddLiteral("where")
				p.AddSpaces()
				p.AddName(2)
				p.AddSpaces()
				p.AddLiteral("=")
				p.AddSpaces()
				p.AddLiteral("(select ")
				p.AddNumber(3, 1337)
				p.AddLiteral(")")
				return p
			},
		},
		{
			Form: "hi or a=a",
			Make: func() (sample string) {
				sample += sampleName()
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				name := sampleName()
				sample += name
				sample += "="
				sample += name
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddName(0)
				p.AddOr()
				p.AddName(1)
				p.AddLiteral("=")
				p.AddName(1)
				return p
			},
		},
		{
			Form: "*(|(mail=*))",
			Make: func() (sample string) {
				sample += "*(|("
				sample += sampleName()
				sample += "=*))"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("*(|(")
				p.AddName(0)
				p.AddLiteral("=*))")
				return p
			},
		},
		{
			Form: "password:*/=1--",
			Make: func() (sample string) {
				sample += "password:*/="
				sample += sampleNumber(1337)
				sample += "--"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("password:*/=")
				p.AddNumber(0, 1337)
				p.AddLiteral("--")
				return p
			},
		},
		{
			Form: "distinct",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += "distinct"
				sample += sampleSpaces()
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpacesOptional()
				p.AddLiteral("distinct")
				p.AddSpacesOptional()
				return p
			},
		},
		{
			Form:     ");waitfor delay '0:0:__TIME__'--",
			Abstract: true,
			Make: func() (sample string) {
				sample += ");waitfor"
				sample += sampleSpaces()
				sample += "delay"
				sample += sampleSpaces()
				sample += "'"
				sample += sampleNumber(24)
				sample += ":"
				sample += sampleNumber(60)
				sample += ":"
				sample += sampleNumber(60)
				sample += "'--"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral(")")
				p.AddWaitfor()
				return p
			},
		},
		{
			Form: "to_timestamp_tz",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += "to_timestamp_tz"
				sample += sampleSpaces()
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpacesOptional()
				p.AddLiteral("to_timestamp_tz")
				p.AddSpacesOptional()
				return p
			},
		},
		{
			Form: "\") or benchmark(10000000,MD5(1))#",
			Make: func() (sample string) {
				sample += "\")"
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += sampleBenchmark()
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("\")")
				p.AddOr()
				p.AddBenchmark()
				return p
			},
		},
		{
			Form: " UNION SELECT",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += "union"
				sample += sampleSpaces()
				sample += "select"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpaces()
				p.AddLiteral("union")
				p.AddSpaces()
				p.AddLiteral("select")
				return p
			},
		},
		{
			Form: "%2A%28%7C%28mail%3D%2A%29%29",
			Make: func() (sample string) {
				sample += sampleHexSpaces()
				sample += "%2A%28%7C%28"
				sample += sampleName()
				sample += "%3D%2A%29%29"
				sample += sampleHexSpaces()
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddHexSpaces()
				p.AddLiteral("%2A%28%7C%28")
				p.AddName(0)
				p.AddLiteral("%3D%2A%29%29")
				p.AddHexSpaces()
				return p
			},
		},
		{
			Form: "+sqlvuln",
			Make: func() (sample string) {
				sample += "+"
				sample += sampleName()
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("+")
				p.AddSQL()
				return p
			},
		},
		{
			Form: " or 1=1 /*",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				number := sampleNumber(1337)
				sample += number
				sample += "="
				sample += number
				sample += sampleSpaces()
				sample += "/*"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddOr()
				p.AddNumber(0, 1337)
				p.AddLiteral("=")
				p.AddNumber(0, 1337)
				p.AddSpaces()
				p.AddLiteral("/*")
				return p
			},
		},
		{
			Form:     ")) or sleep(__TIME__)='",
			Abstract: true,
			Make: func() (sample string) {
				sample += "))"
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += "sleep("
				sample += sampleNumber(1337)
				sample += ")='"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("))")
				p.AddOr()
				p.AddLiteral("sleep(")
				p.AddSpacesOptional()
				p.AddNumber(0, 1337)
				p.AddSpacesOptional()
				p.AddLiteral(")='")
				return p
			},
		},
		{
			Form: "or 1=1 or \"\"=",
			Make: func() (sample string) {
				sample += sampleOr()
				sample += sampleSpaces()
				number := sampleNumber(1337)
				sample += number
				sample += "="
				sample += number
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += "\"\"="
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddOr()
				p.AddNumber(0, 1337)
				p.AddLiteral("=")
				p.AddNumber(0, 1337)
				p.AddOr()
				p.AddLiteral("\"\"=")
				return p
			},
		},
		{
			Form: " or 1 in (select @@version)--",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += sampleNumber(1337)
				sample += sampleSpaces()
				sample += "in"
				sample += sampleSpaces()
				sample += "(select"
				sample += sampleSpaces()
				sample += "@@"
				sample += sampleName()
				sample += ")--"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddOr()
				p.AddNumber(0, 1337)
				p.AddSpaces()
				p.AddLiteral("in")
				p.AddSpaces()
				p.AddLiteral("(select")
				p.AddSpaces()
				p.AddLiteral("@@")
				p.AddName(1)
				p.AddLiteral(")--")
				return p
			},
		},
		{
			Form: "sqlvuln;",
			Make: func() (sample string) {
				sample += sampleName()
				sample += ";"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddSQL()
				p.AddLiteral(";")
				return p
			},
		},
		{
			Form:     " union select * from users where login = char ...",
			Abstract: true,
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += "union"
				sample += sampleSpaces()
				sample += "select"
				sample += sampleSpaces()
				sample += "*"
				sample += sampleSpaces()
				sample += "from"
				sample += sampleSpaces()
				sample += sampleName()
				sample += sampleSpaces()
				sample += "where"
				sample += sampleSpaces()
				sample += sampleName()
				sample += sampleSpaces()
				sample += "="
				sample += sampleSpaces()
				sample += "char"
				sample += sampleSpaces()
				for i := 0; i < 7; i++ {
					sample += sampleNumber(256)
					sample += ","
				}
				sample += sampleNumber(256)
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpaces()
				p.AddLiteral("union")
				p.AddSpaces()
				p.AddLiteral("select")
				p.AddSpaces()
				p.AddLiteral("*")
				p.AddSpaces()
				p.AddLiteral("from")
				p.AddSpaces()
				p.AddName(0)
				p.AddSpaces()
				p.AddLiteral("where")
				p.AddSpaces()
				p.AddName(1)
				p.AddSpaces()
				p.AddLiteral("=")
				p.AddSpaces()
				p.AddLiteral("char")
				p.AddSpaces()
				p.AddNumberList(256)
				return p
			},
		},
		{
			Form: "x' or 1=1 or 'x'='y",
			Make: func() (sample string) {
				sample += sampleName()
				sample += "'"
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				number := sampleNumber(1337)
				sample += number
				sample += "="
				sample += number
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += "'"
				sample += sampleName()
				sample += "'='"
				sample += sampleName()
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddName(0)
				p.AddLiteral("'")
				p.AddOr()
				p.AddNumber(1, 1337)
				p.AddLiteral("=")
				p.AddNumber(1, 1337)
				p.AddOr()
				p.AddLiteral("'")
				p.AddName(2)
				p.AddLiteral("'='")
				p.AddName(2)
				return p
			},
		},
		{
			Form: "28 %",
			Make: func() (sample string) {
				sample += sampleNumber(1337)
				sample += sampleSpaces()
				sample += "%"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddNumber(0, 1337)
				p.AddSpaces()
				p.AddLiteral("%")
				return p
			},
		},
		{
			Form: "â or 3=3 --",
			Make: func() (sample string) {
				sample += sampleName()
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				number := sampleNumber(1337)
				sample += number
				sample += "="
				sample += number
				sample += sampleSpaces()
				sample += "--"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddName(0)
				p.AddOr()
				p.AddNumber(0, 1337)
				p.AddLiteral("=")
				p.AddNumber(0, 1337)
				p.AddSpaces()
				p.AddLiteral("--")
				return p
			},
		},
		{
			Form: "@variable",
			Make: func() (sample string) {
				sample += "@"
				sample += sampleName()
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("@")
				p.AddName(0)
				return p
			},
		},
		{
			Form: " or '1'='1'--",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += "'"
				number := sampleNumber(1337)
				sample += number
				sample += "'='"
				sample += number
				sample += "'--"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddOr()
				p.AddLiteral("'")
				p.AddNumber(0, 1337)
				p.AddLiteral("'='")
				p.AddNumber(0, 1337)
				p.AddLiteral("'--")
				return p
			},
		},
		{
			Form: "\"a\"\" or 1=1--\"",
			Make: func() (sample string) {
				sample += "\""
				sample += sampleName()
				sample += "\"\""
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				number := sampleNumber(1337)
				sample += number
				sample += "="
				sample += number
				sample += "--\""
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("\"")
				p.AddName(0)
				p.AddLiteral("\"\"")
				p.AddOr()
				p.AddNumber(1, 1337)
				p.AddLiteral("=")
				p.AddNumber(1, 1337)
				p.AddLiteral("--\"")
				return p
			},
		},
		{
			Form: "//*",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += "//*"
				sample += sampleSpaces()
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpacesOptional()
				p.AddLiteral("//*")
				p.AddSpacesOptional()
				return p
			},
		},
		{
			Form: "%2A%7C",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += "%2A%7C"
				sample += sampleSpaces()
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpacesOptional()
				p.AddLiteral("%2A%7C")
				p.AddSpacesOptional()
				return p
			},
		},
		{
			Form: "\" or 0=0 --",
			Make: func() (sample string) {
				sample += "\""
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				number := sampleNumber(1337)
				sample += number
				sample += "="
				sample += number
				sample += sampleSpaces()
				sample += "--"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("\"")
				p.AddOr()
				p.AddNumber(0, 1337)
				p.AddLiteral("=")
				p.AddNumber(0, 1337)
				p.AddSpaces()
				p.AddLiteral("--")
				return p
			},
		},
		{
			Form:     "\")) or pg_sleep(__TIME__)--",
			Abstract: true,
			Make: func() (sample string) {
				sample += "\"))"
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += "pg_sleep("
				sample += sampleNumber(1337)
				sample += ")--"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("\"))")
				p.AddOr()
				p.AddLiteral("pg_sleep(")
				p.AddSpacesOptional()
				p.AddNumber(0, 1337)
				p.AddSpacesOptional()
				p.AddLiteral(")--")
				return p
			},
		},
		{
			Form: "?",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += "?"
				sample += sampleSpaces()
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpacesOptional()
				p.AddLiteral("?")
				p.AddSpacesOptional()
				return p
			},
		},
		{
			Form: " or 1/*",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += sampleNumber(1337)
				sample += "/*"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddOr()
				p.AddNumber(0, 1337)
				p.AddLiteral("/*")
				return p
			},
		},
		{
			Form: "!",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += "!"
				sample += sampleSpaces()
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpacesOptional()
				p.AddLiteral("!")
				p.AddSpacesOptional()
				return p
			},
		},
		{
			Form: "'",
			Make: func() (sample string) {
				sample += "'"
				sample += sampleSpaces()
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("'")
				p.AddSpacesOptional()
				return p
			},
		},
		{
			Form: " or a = a",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				name := sampleName()
				sample += name
				sample += sampleSpaces()
				sample += "="
				sample += sampleSpaces()
				sample += name
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddOr()
				p.AddName(0)
				p.AddSpaces()
				p.AddLiteral("=")
				p.AddSpaces()
				p.AddName(0)
				return p
			},
		},
		{
			Form: "declare @q nvarchar (200) select @q = 0x770061006900740066006F0072002000640065006C00610079002000270030003A0030003A0031003000270000 exec(@q)",
			Make: func() (sample string) {
				sample += "declare"
				sample += sampleSpaces()
				sample += "@"
				name := sampleName()
				sample += name
				sample += sampleSpaces()
				sample += "nvarchar"
				sample += sampleSpaces()
				sample += "("
				sample += sampleNumber(200)
				sample += ")"
				sample += sampleSpaces()
				sample += "select"
				sample += sampleSpaces()
				sample += "@"
				sample += name
				sample += sampleSpaces()
				sample += "="
				sample += sampleSpaces()
				sample += sampleHex(1337 * 1337)
				sample += sampleSpaces()
				sample += "exec(@"
				sample += name
				sample += ")"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("declare")
				p.AddSpaces()
				p.AddLiteral("@")
				p.AddName(0)
				p.AddSpaces()
				p.AddLiteral("nvarchar")
				p.AddSpaces()
				p.AddLiteral("(")
				p.AddNumber(1, 200)
				p.AddLiteral(")")
				p.AddSpaces()
				p.AddLiteral("select")
				p.AddSpaces()
				p.AddLiteral("@")
				p.AddName(0)
				p.AddSpaces()
				p.AddLiteral("=")
				p.AddSpaces()
				p.AddHex(1337 * 1337)
				p.AddSpaces()
				p.AddLiteral("exec(@")
				p.AddName(0)
				p.AddLiteral(")")
				return p
			},
		},
		{
			Form: "declare @s varchar(200) select @s = 0x77616974666F722064656C61792027303A303A31302700 exec(@s) ",
			Make: func() (sample string) {
				sample += "declare"
				sample += sampleSpaces()
				sample += "@"
				name := sampleName()
				sample += name
				sample += sampleSpaces()
				sample += "varchar("
				sample += sampleNumber(200)
				sample += ")"
				sample += sampleSpaces()
				sample += "select"
				sample += sampleSpaces()
				sample += "@"
				sample += name
				sample += sampleSpaces()
				sample += "="
				sample += sampleSpaces()
				sample += sampleHex(1337 * 1337)
				sample += sampleSpaces()
				sample += "exec(@"
				sample += name
				sample += ")"
				sample += sampleSpaces()
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("declare")
				p.AddSpaces()
				p.AddLiteral("@")
				p.AddName(0)
				p.AddSpaces()
				p.AddLiteral("varchar(")
				p.AddNumber(1, 200)
				p.AddLiteral(")")
				p.AddSpaces()
				p.AddLiteral("select")
				p.AddSpaces()
				p.AddLiteral("@")
				p.AddName(0)
				p.AddSpaces()
				p.AddLiteral("=")
				p.AddSpaces()
				p.AddHex(1337 * 1337)
				p.AddSpaces()
				p.AddLiteral("exec(@")
				p.AddName(0)
				p.AddLiteral(")")
				p.AddSpaces()
				return p
			},
		},
		{
			Form: "declare @q nvarchar (200) 0x730065006c00650063007400200040004000760065007200730069006f006e00 exec(@q)",
			Make: func() (sample string) {
				sample += "declare"
				sample += sampleSpaces()
				sample += "@"
				name := sampleName()
				sample += name
				sample += sampleSpaces()
				sample += "nvarchar"
				sample += sampleSpaces()
				sample += "("
				sample += sampleNumber(200)
				sample += ")"
				sample += sampleSpaces()
				sample += sampleHex(1337 * 1337)
				sample += sampleSpaces()
				sample += "exec(@"
				sample += name
				sample += ")"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("declare")
				p.AddSpaces()
				p.AddLiteral("@")
				p.AddName(0)
				p.AddSpaces()
				p.AddLiteral("nvarchar")
				p.AddSpaces()
				p.AddLiteral("(")
				p.AddNumber(1, 200)
				p.AddLiteral(")")
				p.AddSpaces()
				p.AddHex(1337 * 1337)
				p.AddSpaces()
				p.AddLiteral("exec(@")
				p.AddName(0)
				p.AddLiteral(")")
				return p
			},
		},
		{
			Form: "declare @s varchar (200) select @s = 0x73656c65637420404076657273696f6e exec(@s)",
			Make: func() (sample string) {
				sample += "declare"
				sample += sampleSpaces()
				sample += "@"
				name := sampleName()
				sample += name
				sample += sampleSpaces()
				sample += "varchar"
				sample += sampleSpaces()
				sample += "("
				sample += sampleNumber(200)
				sample += ")"
				sample += sampleSpaces()
				sample += "select"
				sample += sampleSpaces()
				sample += "@"
				sample += name
				sample += sampleSpaces()
				sample += "="
				sample += sampleSpaces()
				sample += sampleHex(1337 * 1337)
				sample += sampleSpaces()
				sample += "exec(@"
				sample += name
				sample += ")"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("declare")
				p.AddSpaces()
				p.AddLiteral("@")
				p.AddName(0)
				p.AddSpaces()
				p.AddLiteral("varchar")
				p.AddSpaces()
				p.AddLiteral("(")
				p.AddNumber(1, 200)
				p.AddLiteral(")")
				p.AddSpaces()
				p.AddLiteral("select")
				p.AddSpaces()
				p.AddLiteral("@")
				p.AddName(0)
				p.AddSpaces()
				p.AddLiteral("=")
				p.AddSpaces()
				p.AddHex(1337 * 1337)
				p.AddSpaces()
				p.AddLiteral("exec(@")
				p.AddName(0)
				p.AddLiteral(")")
				return p
			},
		},
		{
			Form: "' or 1=1",
			Make: func() (sample string) {
				sample += "'"
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				number := sampleNumber(1337)
				sample += number
				sample += "="
				sample += number
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("'")
				p.AddOr()
				p.AddNumber(0, 1337)
				p.AddLiteral("=")
				p.AddNumber(0, 1337)
				return p
			},
		},
		{
			Form: " or 1=1 --",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				number := sampleNumber(1337)
				sample += number
				sample += "="
				sample += number
				sample += sampleSpaces()
				sample += "--"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddOr()
				p.AddNumber(0, 1337)
				p.AddLiteral("=")
				p.AddNumber(0, 1337)
				p.AddSpaces()
				p.AddLiteral("--")
				return p
			},
		},
		{
			Form: "x' OR full_name LIKE '%Bob%",
			Make: func() (sample string) {
				sample += sampleName()
				sample += "'"
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += sampleName()
				sample += sampleSpaces()
				sample += "like"
				sample += sampleSpaces()
				sample += "'%"
				sample += sampleName()
				sample += "%"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddName(0)
				p.AddLiteral("'")
				p.AddOr()
				p.AddName(1)
				p.AddSpaces()
				p.AddLiteral("like")
				p.AddSpaces()
				p.AddLiteral("'%")
				p.AddName(2)
				p.AddLiteral("%")
				return p
			},
		},
		{
			Form: "'; exec master..xp_cmdshell 'ping 172.10.1.255'--",
			Make: func() (sample string) {
				sample += "';"
				sample += sampleSpaces()
				sample += "exec"
				sample += sampleSpaces()
				sample += "master..xp_cmdshell"
				sample += sampleSpaces()
				sample += "'ping"
				sample += sampleSpaces()
				sample += sampleNumber(256)
				sample += "."
				sample += sampleNumber(256)
				sample += "."
				sample += sampleNumber(256)
				sample += "."
				sample += sampleNumber(256)
				sample += "'--"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("';")
				p.AddSpaces()
				p.AddLiteral("exec")
				p.AddSpaces()
				p.AddLiteral("master..xp_cmdshell")
				p.AddSpaces()
				p.AddLiteral("'ping")
				p.AddSpaces()
				p.AddNumber(0, 256)
				p.AddLiteral(".")
				p.AddNumber(1, 256)
				p.AddLiteral(".")
				p.AddNumber(2, 256)
				p.AddLiteral(".")
				p.AddNumber(3, 256)
				p.AddLiteral("'--")
				return p
			},
		},
		{
			Form: "'%20or%20''='",
			Make: func() (sample string) {
				sample += "'"
				sample += sampleHexSpaces()
				sample += sampleOr()
				sample += sampleHexSpaces()
				sample += "''='"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("'")
				p.AddHexOr()
				p.AddLiteral("''='")
				return p
			},
		},
		{
			Form: "'%20or%20'x'='x",
			Make: func() (sample string) {
				sample += "'"
				sample += sampleHexSpaces()
				sample += sampleOr()
				sample += sampleHexSpaces()
				sample += "'"
				name := sampleName()
				sample += name
				sample += "'='"
				sample += name
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("'")
				p.AddHexOr()
				p.AddLiteral("'")
				p.AddName(0)
				p.AddLiteral("'='")
				p.AddName(0)
				return p
			},
		},
		{
			Form: "')%20or%20('x'='x",
			Make: func() (sample string) {
				sample += "')"
				sample += sampleHexSpaces()
				sample += sampleOr()
				sample += sampleHexSpaces()
				sample += "('"
				name := sampleName()
				sample += name
				sample += "'='"
				sample += name
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("')")
				p.AddHexOr()
				p.AddLiteral("('")
				p.AddName(0)
				p.AddLiteral("'='")
				p.AddName(0)
				return p
			},
		},
		{
			Form: "' or 0=0 --",
			Make: func() (sample string) {
				sample += "'"
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				number := sampleNumber(1337)
				sample += number
				sample += "="
				sample += number
				sample += sampleSpaces()
				sample += "--"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("'")
				p.AddOr()
				p.AddNumber(0, 1337)
				p.AddLiteral("=")
				p.AddNumber(0, 1337)
				p.AddSpaces()
				p.AddLiteral("--")
				return p
			},
		},
		{
			Form: "' or 0=0 #",
			Make: func() (sample string) {
				sample += "'"
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				number := sampleNumber(1337)
				sample += number
				sample += "="
				sample += number
				sample += sampleSpaces()
				sample += "#"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddOr()
				p.AddNumber(0, 1337)
				p.AddLiteral("=")
				p.AddNumber(0, 1337)
				p.AddSpaces()
				p.AddLiteral("#")
				return p
			},
		},
		{
			Form: " or 0=0 #\"",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				number := sampleNumber(1337)
				sample += number
				sample += "="
				sample += number
				sample += sampleSpaces()
				sample += "#\""
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddOr()
				p.AddNumber(0, 1337)
				p.AddLiteral("=")
				p.AddNumber(0, 1337)
				p.AddSpaces()
				p.AddLiteral("#\"")
				return p
			},
		},
		{
			Form: "' or 1=1--",
			Make: func() (sample string) {
				sample += "'"
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				number := sampleNumber(1337)
				sample += number
				sample += "="
				sample += number
				sample += "--"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("'")
				p.AddOr()
				p.AddNumber(0, 1337)
				p.AddLiteral("=")
				p.AddNumber(0, 1337)
				p.AddLiteral("--")
				return p
			},
		},
		{
			Form: "' or '1'='1'--",
			Make: func() (sample string) {
				sample += "'"
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += "'"
				number := sampleNumber(1337)
				sample += number
				sample += "'='"
				sample += number
				sample += "'--"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("'")
				p.AddOr()
				p.AddLiteral("'")
				p.AddNumber(0, 1337)
				p.AddLiteral("'='")
				p.AddNumber(0, 1337)
				p.AddLiteral("'--")
				return p
			},
		},
		{
			Form: "' or 1 --'",
			Make: func() (sample string) {
				sample += "'"
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += sampleNumber(1337)
				sample += sampleSpaces()
				sample += "--'"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("'")
				p.AddOr()
				p.AddNumber(0, 1337)
				p.AddSpaces()
				p.AddLiteral("--'")
				return p
			},
		},
		{
			Form: "or 1=1--",
			Make: func() (sample string) {
				sample += sampleOr()
				sample += sampleSpaces()
				number := sampleNumber(1337)
				sample += number
				sample += "="
				sample += number
				sample += "--"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddOr()
				p.AddNumber(0, 1337)
				p.AddLiteral("=")
				p.AddNumber(0, 1337)
				p.AddLiteral("--")
				return p
			},
		},
		{
			Form: "' or 1=1 or ''='",
			Make: func() (sample string) {
				sample += "'"
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				number := sampleNumber(1337)
				sample += number
				sample += "="
				sample += number
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += "''='"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("'")
				p.AddOr()
				p.AddNumber(0, 1337)
				p.AddLiteral("=")
				p.AddNumber(0, 1337)
				p.AddOr()
				p.AddLiteral("''='")
				return p
			},
		},
		{
			Form: " or 1=1 or \"\"=",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				number := sampleNumber(1337)
				sample += number
				sample += "="
				sample += number
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += "\"\"="
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddOr()
				p.AddNumber(0, 1337)
				p.AddLiteral("=")
				p.AddNumber(0, 1337)
				p.AddOr()
				p.AddLiteral("\"\"=")
				return p
			},
		},
		{
			Form: "' or a=a--",
			Make: func() (sample string) {
				sample += "'"
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				name := sampleName()
				sample += name
				sample += "="
				sample += name
				sample += "--"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("'")
				p.AddOr()
				p.AddName(0)
				p.AddLiteral("=")
				p.AddName(0)
				p.AddLiteral("--")
				return p
			},
		},
		{
			Form: " or a=a",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				name := sampleName()
				sample += name
				sample += "="
				sample += name
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddOr()
				p.AddName(0)
				p.AddLiteral("=")
				p.AddName(0)
				return p
			},
		},
		{
			Form: "') or ('a'='a",
			Make: func() (sample string) {
				sample += "')"
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += "('"
				name := sampleName()
				sample += name
				sample += "'='"
				sample += name
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("')")
				p.AddOr()
				p.AddLiteral("('")
				p.AddName(0)
				p.AddLiteral("'='")
				p.AddName(0)
				return p
			},
		},
		{
			Form: "'hi' or 'x'='x';",
			Make: func() (sample string) {
				sample += "'"
				sample += sampleName()
				sample += "'"
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += "'"
				name := sampleName()
				sample += name
				sample += "'='"
				sample += name
				sample += "'"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("'")
				p.AddName(0)
				p.AddLiteral("'")
				p.AddOr()
				p.AddLiteral("'")
				p.AddName(1)
				p.AddLiteral("'='")
				p.AddName(1)
				p.AddLiteral("'")
				return p
			},
		},
		{
			Form: "or",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpacesOptional()
				p.AddLiteral("or")
				p.AddSpacesOptional()
				return p
			},
		},
		{
			Form: "procedure",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += "procedure"
				sample += sampleSpaces()
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpacesOptional()
				p.AddLiteral("procedure")
				p.AddSpacesOptional()
				return p
			},
		},
		{
			Form: "handler",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += "handler"
				sample += sampleSpaces()
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpacesOptional()
				p.AddLiteral("handler")
				p.AddSpacesOptional()
				return p
			},
		},
		{
			Form: "' or username like '%",
			Make: func() (sample string) {
				sample += "'"
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += sampleName()
				sample += sampleSpaces()
				sample += "like"
				sample += sampleSpaces()
				sample += "'%"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("'")
				p.AddOr()
				p.AddName(0)
				p.AddSpaces()
				p.AddLiteral("like")
				p.AddSpaces()
				p.AddLiteral("'%")
				return p
			},
		},
		{
			Form: "' or uname like '%",
		},
		{
			Form: "' or userid like '%",
		},
		{
			Form: "' or uid like '%",
		},
		{
			Form: "' or user like '%",
		},
		{
			Form: "'; exec master..xp_cmdshell",
			Make: func() (sample string) {
				sample += "';"
				sample += sampleSpaces()
				sample += "exec"
				sample += sampleSpaces()
				sample += "master..xp_cmdshell"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("';")
				p.AddSpaces()
				p.AddLiteral("exec")
				p.AddSpaces()
				p.AddLiteral("master..xp_cmdshell")
				return p
			},
		},
		{
			Form: "'; exec xp_regread",
			Make: func() (sample string) {
				sample += "';"
				sample += sampleSpaces()
				sample += "exec"
				sample += sampleSpaces()
				sample += "xp_regread"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("';")
				p.AddSpaces()
				p.AddLiteral("exec")
				p.AddSpaces()
				p.AddLiteral("xp_regread")
				return p
			},
		},
		{
			Form: "t'exec master..xp_cmdshell 'nslookup www.google.com'--",
			Make: func() (sample string) {
				sample += "t'exec"
				sample += sampleSpaces()
				sample += "master..xp_cmdshell"
				sample += sampleSpaces()
				sample += "'nslookup"
				sample += sampleSpaces()
				sample += sampleName()
				sample += "."
				sample += sampleName()
				sample += "."
				sample += sampleName()
				sample += "'--"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("t'exec")
				p.AddSpaces()
				p.AddLiteral("master..xp_cmdshell")
				p.AddSpaces()
				p.AddLiteral("'nslookup")
				p.AddSpaces()
				p.AddName(0)
				p.AddLiteral(".")
				p.AddName(1)
				p.AddLiteral(".")
				p.AddName(2)
				p.AddLiteral("'--")
				return p
			},
		},
		{
			Form: "--sp_password",
			Make: func() (sample string) {
				sample += "--"
				sample += sampleSpaces()
				sample += "sp_password"
				sample += sampleSpaces()
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("--")
				p.AddSpaces()
				p.AddLiteral("sp_password")
				p.AddSpaces()
				return p
			},
		},
		{
			Form: "' UNION SELECT",
			Make: func() (sample string) {
				sample += "'"
				sample += sampleSpaces()
				sample += "union"
				sample += sampleSpaces()
				sample += "select"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("'")
				p.AddSpaces()
				p.AddLiteral("union")
				p.AddSpaces()
				p.AddLiteral("select")
				return p
			},
		},
		{
			Form: "' UNION ALL SELECT",
			Make: func() (sample string) {
				sample += "'"
				sample += sampleSpaces()
				sample += "union"
				sample += sampleSpaces()
				sample += "all"
				sample += sampleSpaces()
				sample += "select"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("'")
				p.AddSpaces()
				p.AddLiteral("union")
				p.AddSpaces()
				p.AddLiteral("all")
				p.AddSpaces()
				p.AddLiteral("select")
				return p
			},
		},
		{
			Form: "' or (EXISTS)",
			Make: func() (sample string) {
				sample += "'"
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += "(exists)"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("'")
				p.AddOr()
				p.AddLiteral("(exists)")
				return p
			},
		},
		{
			Form: "' (select top 1",
			Make: func() (sample string) {
				sample += "'"
				sample += sampleSpaces()
				sample += "(select"
				sample += sampleSpaces()
				sample += "top"
				sample += sampleSpaces()
				sample += sampleNumber(1337)
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("'")
				p.AddSpaces()
				p.AddLiteral("(select")
				p.AddSpaces()
				p.AddLiteral("top")
				p.AddSpaces()
				p.AddNumber(0, 1337)
				return p
			},
		},
		{
			Form: "'||UTL_HTTP.REQUEST",
			Make: func() (sample string) {
				sample += "'"
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += "utl_http.request"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("'")
				p.AddOr()
				p.AddLiteral("utl_http.request")
				return p
			},
		},
		{
			Form: "1;SELECT%20*",
			Make: func() (sample string) {
				sample += sampleNumber(1337)
				sample += ";"
				sample += "select"
				sample += sampleHexSpaces()
				sample += "*"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddNumber(0, 1337)
				p.AddLiteral(";select")
				p.AddHexSpaces()
				p.AddLiteral("*")
				return p
			},
		},
		{
			Form: "<>\"'%;)(&+",
		},
		{
			Form: "'%20or%201=1",
			Make: func() (sample string) {
				sample += "'"
				sample += sampleHexSpaces()
				sample += sampleOr()
				sample += sampleHexSpaces()
				number := sampleNumber(1337)
				sample += number
				sample += "="
				sample += number
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("'")
				p.AddHexOr()
				p.AddNumber(0, 1337)
				p.AddLiteral("=")
				p.AddNumber(0, 1337)
				return p
			},
		},
		{
			Form: "'sqlattempt1",
			Make: func() (sample string) {
				sample += "'"
				sample += sampleName()
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("'")
				p.AddSQL()
				return p
			},
		},
		{
			Form: "%28",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += "%"
				sample += sampleNumber(256)
				sample += sampleSpaces()
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpacesOptional()
				p.AddLiteral("%")
				p.AddNumber(0, 1337)
				p.AddSpacesOptional()
				return p
			},
		},
		{
			Form: "%29",
		},
		{
			Form: "%26",
		},
		{
			Form: "%21",
		},
		{
			Form: "' or ''='",
			Make: func() (sample string) {
				sample += "'"
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += "''='"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("'")
				p.AddOr()
				p.AddLiteral("''='")
				return p
			},
		},
		{
			Form: "' or 3=3",
			Make: func() (sample string) {
				sample += "'"
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				number := sampleNumber(1337)
				sample += number
				sample += "="
				sample += number
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("'")
				p.AddOr()
				p.AddNumber(0, 1337)
				p.AddLiteral("=")
				p.AddNumber(0, 1337)
				return p
			},
		},
		{
			Form: " or 3=3 --",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				number := sampleNumber(1337)
				sample += number
				sample += "="
				sample += number
				sample += sampleSpaces()
				sample += "--"
				return
			},
			Regex: func() *Parts {
				p := NewParts()
				p.AddName(0)
				p.AddOr()
				p.AddNumber(1, 1337)
				p.AddLiteral("=")
				p.AddNumber(1, 1337)
				p.AddLiteral("--")
				return p
			},
		},
	}
	return generators
}

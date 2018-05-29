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
	Form string
	Make func() (sample string)
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
		},
		{
			Form: "benchmark(10000000,MD5(1))#",
			Make: func() (sample string) {
				sample += sampleBenchmark()
				return
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
		},
		{
			Form: "\";waitfor delay '0:0:__TIME__'--",
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
		},
		{
			Form: "1) or pg_sleep(__TIME__)--",
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
		},
		{
			Form: "delete",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += "delete"
				sample += sampleSpaces()
				return
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
		},
		{
			Form: "\" or sleep(__TIME__)#",
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
		},
		{
			Form: "pg_sleep(__TIME__)--",
			Make: func() (sample string) {
				sample += "pg_sleep("
				sample += sampleNumber(1337)
				sample += ")--"
				return
			},
		},
		{
			Form: "*(|(objectclass=*))",
		},
		{
			Form: "declare @q nvarchar (200) 0x730065006c00650063 ...",
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
		},
		{
			Form: "insert",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += "insert"
				sample += sampleSpaces()
				return
			},
		},
		{
			Form: "1) or sleep(__TIME__)#",
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
		},
		{
			Form: "asc",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += "asc"
				sample += sampleSpaces()
				return
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
		},
		{
			Form: "hi or 1=1 --\"",
			Make: func() (sample string) {
				sample += sampleName()
				sample += sampleSpaces()
				sample += sampleOr()
				number := sampleNumber(1337)
				sample += number
				sample += "="
				sample += number
				sample += sampleSpaces()
				sample += "--\""
				return
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
		},
		{
			Form: ") or sleep(__TIME__)='",
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
		},
		{
			Form: "0",
			Make: func() (sample string) {
				sample += sampleNumber(1337)
				return
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
		},
		{
			Form: "limit",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += "limit"
				sample += sampleSpaces()
				return
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
		},
		{
			Form: "PRINT",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += "print"
				sample += sampleSpaces()
				return
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
		},
	}
	return generators
}

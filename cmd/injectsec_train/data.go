// Copyright 2018 The InjectSec Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"math/rand"
)

// Generator generates training data
type Generator struct {
	Form  string
	Case  string
	Skip  bool
	Regex func() *Parts
}

// TrainingDataGenerator returns a data generator
func TrainingDataGenerator(rnd *rand.Rand) []Generator {
	generators := []Generator{
		// Generic-SQLi.txt
		{
			Form: ")%20or%20('x'='x",
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
			Regex: func() *Parts {
				p := NewParts()
				p.AddBenchmark()
				return p
			},
		},
		{
			Form: "update",
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpacesOptional()
				p.AddLiteral("update")
				p.AddSpacesOptional()
				return p
			},
		},
		{
			Form: "\";waitfor delay '0:0:__TIME__'--",
			Case: "\";waitfor delay '0:0:24'--",
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("\"")
				p.AddWaitfor()
				return p
			},
		},
		{
			Form: "1) or pg_sleep(__TIME__)--",
			Case: "1) or pg_sleep(123)--",
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
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpacesOptional()
				p.AddLiteral("like")
				p.AddSpacesOptional()
				return p
			},
		},
		{
			Form: "\" or sleep(__TIME__)#",
			Case: "\" or sleep(123)#",
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
			Form: "pg_sleep(__TIME__)--",
			Case: "pg_sleep(123)--",
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
			Form: "declare @q nvarchar (200) 0x730065006c00650063 ...",
			Case: "declare @q nvarchar (200) 0x730065006c00650063",
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
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpacesOptional()
				p.AddLiteral("insert")
				p.AddSpacesOptional()
				return p
			},
		},
		{
			Form: "1) or sleep(__TIME__)#",
			Case: "1) or sleep(567)#",
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
				p.AddLiteral("--")
				return p
			},
		},
		{
			Form: "1)) or benchmark(10000000,MD5(1))#",
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
			Form: ") or sleep(__TIME__)='",
			Case: ") or sleep(123)='",
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
			Regex: func() *Parts {
				p := NewParts()
				p.AddNumber(0, 1337)
				return p
			},
		},
		{
			Form: "21 %",
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
			Form: "));waitfor delay '0:0:__TIME__'--",
			Case: "));waitfor delay '0:0:42'--",
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("))")
				p.AddWaitfor()
				return p
			},
		},
		{
			Form: "a' waitfor delay '0:0:10'--",
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
			Form: "1;(load_file(char(47,101,116,99,47,112,97,115, ...",
			Case: "1;(load_file(char(47,101,116,99,47,112,97,115)))",
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
			Form: "1 or sleep(__TIME__)#",
			Case: "1 or sleep(123)#",
			Regex: func() *Parts {
				p := NewParts()
				p.AddNumber(0, 1337)
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
			Form: "or 1=1",
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
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpacesOptional()
				p.AddLiteral("--")
				return p
			},
		},
		{
			Form: " or 1=1 or ''='",
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
			Form: "declare @s varchar (200) select @s = 0x73656c6 ...",
			Case: "declare @s varchar (200) select @s = 0x73656c6",
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
			Regex: func() *Parts {
				p := NewParts()
				p.AddType(PartTypeScientificNumber)
				return p
			},
		},
		{
			Form: "\" or pg_sleep(__TIME__)--",
			Case: "\" or pg_sleep(123)--",
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("\"")
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
			Form: "x' AND email IS NULL; --",
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
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("\x27union")
				p.AddSpaces()
				p.AddLiteral("select")
				return p
			},
		},
		{
			Form: "declare @s varchar(200) select @s = 0x77616974 ...",
			Case: "declare @s varchar(200) select @s = 0x77616974",
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
			Case: "select a from b where 1=1",
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpacesOptional()
				p.AddSQL()
				p.AddSpacesOptional()
				return p
			},
		},
		{
			Form: "\"));waitfor delay '0:0:__TIME__'--",
			Case: "\"));waitfor delay '0:0:23'--",
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("\"))")
				p.AddWaitfor()
				return p
			},
		},
		{
			Form: "||6",
			Regex: func() *Parts {
				p := NewParts()
				p.AddOr()
				p.AddNumber(0, 1337)
				return p
			},
		},
		{
			Form: "or%201=1 --",
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
			Form: ") union select * from information_schema.tables;",
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
				p.AddLiteral("from")
				p.AddSpaces()
				p.AddLiteral("information_schema.tables;")
				return p
			},
		},
		{
			Form: "PRINT @@variable",
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
			Case: "(select a from b where 1=1)",
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
			Form: " and 1=( if((load_file(char(110,46,101,120,11 ...",
			Case: " and 1=( if((load_file(char(110,46,101,120,11)))))",
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
			Form: "0x770061006900740066006F0072002000640065006C00 ...",
			Case: "0x770061006900740066006F0072002000640065006C00",
			Regex: func() *Parts {
				p := NewParts()
				p.AddHex(1337 * 1336)
				return p
			},
		},
		{
			Form: "%20'sleep%2050'",
			Regex: func() *Parts {
				p := NewParts()
				p.AddHexSpaces()
				p.AddLiteral("'sleep")
				p.AddHexSpaces()
				p.AddNumber(0, 1337)
				p.AddLiteral("'")
				return p
			},
		},
		{
			Form: "as",
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpacesOptional()
				p.AddLiteral("as")
				p.AddSpacesOptional()
				return p
			},
		},
		{
			Form: "1)) or pg_sleep(__TIME__)--",
			Case: "1)) or pg_sleep(123)--",
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
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral(",@")
				p.AddName(0)
				return p
			},
		},
		{
			Form: "(sqlattempt2)",
			Case: "(select a from b where 1=1)",
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
			Regex: func() *Parts {
				p := NewParts()
				p.AddOr()
				p.AddLiteral("(exists)")
				return p
			},
		},
		{
			Form: "t'exec master..xp_cmdshell 'nslookup www.googl ...",
			Case: "t'exec master..xp_cmdshell 'nslookup www.google.com",
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
				return p
			},
		},
		{
			Form: "%20$(sleep%2050)",
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
			Regex: func() *Parts {
				p := NewParts()
				p.AddHexOr()
				p.AddLiteral("''='")
				return p
			},
		},
		{
			Form: "||UTL_HTTP.REQUEST",
			Regex: func() *Parts {
				p := NewParts()
				p.AddOr()
				p.AddLiteral("utl_http.request")
				p.AddSpacesOptional()
				return p
			},
		},
		{
			Form: " or pg_sleep(__TIME__)--",
			Case: " or pg_sleep(123)--",
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
			Form: "\") or sleep(__TIME__)=\"",
			Case: "\") or sleep(857)=\"",
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
			Form: "; begin declare @var varchar(8000) set @var=' ...",
			Case: "; begin declare @var varchar(8000) set @var='abc'",
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
			Form: "0x77616974666F722064656C61792027303A303A313027 ...",
			Case: "0x77616974666F722064656C61792027303A303A313027",
			Regex: func() *Parts {
				p := NewParts()
				p.AddHex(1337 * 1337)
				return p
			},
		},
		{
			Form: "exec(@s)",
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpacesOptional()
				p.AddLiteral("exec(@")
				p.AddName(0)
				p.AddLiteral(")")
				p.AddSpacesOptional()
				return p
			},
		},
		{
			Form: ") or pg_sleep(__TIME__)--",
			Case: ") or pg_sleep(123)--",
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
			Form: " or sleep(__TIME__)#",
			Case: " or sleep(123)#",
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
			Regex: func() *Parts {
				p := NewParts()
				p.AddName(0)
				p.AddLiteral("'")
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
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpacesOptional()
				p.AddLiteral("|")
				p.AddSpacesOptional()
				return p
			},
		},
		{
			Form: " or sleep(__TIME__)='",
			Case: " or sleep(123)='",
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
			Regex: func() *Parts {
				p := NewParts()
				p.AddName(0)
				p.AddLiteral("'")
				return p
			},
		},
		{
			Form: "\" or isNULL(1/0) /*",
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
			Form: "declare @s varchar (8000) select @s = 0x73656c ...",
			Case: "declare @s varchar (8000) select @s = 0x73656c",
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
			Form: "char%4039%41%2b%40SELECT",
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
			Form: ";waitfor delay '0:0:__TIME__'--",
			Case: ";waitfor delay '0:0:123'--",
			Regex: func() *Parts {
				p := NewParts()
				p.AddWaitfor()
				return p
			},
		},
		{
			Form: "\" or 1=1--",
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
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpacesOptional()
				p.AddLiteral("*")
				p.AddSpacesOptional()
				p.AddLiteral("/*")
				p.AddSpacesOptional()
				return p
			},
		},
		{
			Form: " or 'text' > 't'",
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
			Regex: func() *Parts {
				p := NewParts()
				p.AddOr()
				p.AddBenchmark()
				return p
			},
		},
		{
			Form: "\");waitfor delay '0:0:__TIME__'--",
			Case: "\");waitfor delay '0:0:42'--",
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("\")")
				p.AddWaitfor()
				return p
			},
		},
		{
			Form: "a' or 3=3--",
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
			Regex: func() *Parts {
				p := NewParts()
				p.AddOr()
				p.AddLiteral("''='")
				return p
			},
		},
		{
			Form: "; exec master..xp_cmdshell",
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
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpacesOptional()
				p.AddLiteral("select")
				p.AddSpacesOptional()
				return p
			},
		},
		{
			Form: "\")) or sleep(__TIME__)=\"",
			Case: "\")) or sleep(123)=\"",
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
			Form: "0x730065006c0065006300740020004000400076006500 ...",
			Case: "0x730065006c0065006300740020004000400076006500",
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
			Form: "\") or pg_sleep(__TIME__)--",
			Case: "\") or pg_sleep(123)--",
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
			Form: "1 or pg_sleep(__TIME__)--",
			Case: "1 or pg_sleep(123)--",
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
			Form: ")) or pg_sleep(__TIME__)--",
			Case: ")) or pg_sleep(343)--",
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
			Regex: func() *Parts {
				p := NewParts()
				p.AddName(0)
				p.AddLiteral("'")
				p.AddAnd()
				p.AddLiteral("1=(select")
				p.AddSpaces()
				p.AddLiteral("count(*)")
				p.AddSpaces()
				p.AddLiteral("from")
				p.AddSpaces()
				p.AddName(1)
				p.AddLiteral(");")
				p.AddSpaces()
				p.AddLiteral("--")
				return p
			},
		},
		{
			Form: "&apos;%20OR",
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("&apos;")
				p.AddHexOr()
				return p
			},
		},
		{
			Form: "; or '1'='1'",
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
			Form: "declare @q nvarchar (200) select @q = 0x770061 ...",
			Case: "declare @q nvarchar (200) select @q = 0x770061",
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
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpacesOptional()
				p.AddLiteral(")")
				p.AddSpacesOptional()
				return p
			},
		},
		{
			Form: "1)) or sleep(__TIME__)#",
			Case: "1)) or sleep(123)#",
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
			Form: " select name from syscolumns where id = (sele ...",
			Case: " select name from syscolumns where id = (select 3)",
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
			Regex: func() *Parts {
				p := NewParts()
				p.AddSpacesOptional()
				p.AddLiteral("distinct")
				p.AddSpacesOptional()
				return p
			},
		},
		{
			Form: ");waitfor delay '0:0:__TIME__'--",
			Case: ");waitfor delay '0:0:123'--",
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral(")")
				p.AddWaitfor()
				return p
			},
		},
		{
			Form: "to_timestamp_tz",
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
			Regex: func() *Parts {
				p := NewParts()
				p.AddHexSpacesOptional()
				p.AddLiteral("%2A%28%7C%28")
				p.AddName(0)
				p.AddLiteral("%3D%2A%29%29")
				p.AddHexSpacesOptional()
				return p
			},
		},
		{
			Form: "+sqlvuln",
			Case: "+select a from b where 1=1",
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("+")
				p.AddSQL()
				return p
			},
		},
		{
			Form: " or 1=1 /*",
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
			Form: ")) or sleep(__TIME__)='",
			Case: ")) or sleep(123)='",
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
			Case: "select a from b where 1=1;",
			Regex: func() *Parts {
				p := NewParts()
				p.AddSQL()
				p.AddLiteral(";")
				return p
			},
		},
		{
			Form: " union select * from users where login = char ...",
			Case: " union select * from users where login = char 1, 2, 3",
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
			Form: "@variable",
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("@")
				p.AddName(0)
				return p
			},
		},
		{
			Form: " or '1'='1'--",
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
			Form: "\")) or pg_sleep(__TIME__)--",
			Case: "\")) or pg_sleep(123)--",
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
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("'")
				p.AddSpacesOptional()
				return p
			},
		},
		{
			Form: " or a = a",
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
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("'")
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
				p.AddLiteral("';")
				return p
			},
		},
		{
			Form: "or",
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
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("--")
				p.AddSpacesOptional()
				p.AddLiteral("sp_password")
				p.AddSpacesOptional()
				return p
			},
		},
		{
			Form: "' UNION SELECT",
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
			Case: "'select a from b where 1=1",
			Regex: func() *Parts {
				p := NewParts()
				p.AddLiteral("'")
				p.AddSQL()
				return p
			},
		},
		{
			Form: "%28",
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
	}
	return generators
}

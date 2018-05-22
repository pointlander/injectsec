// Copyright 2018 The InjectSec Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"unicode"

	"github.com/pointlander/injectsec/gru"
)

var (
	rnd *rand.Rand
)

// Example is a training example
type Example struct {
	Data   []byte
	Attack bool
}

// ToMixed returns a mixed case string
func ToMixed(a string) string {
	b := strings.Builder{}
	b.Grow(len(a))
	for _, v := range a {
		switch rnd.Intn(8) {
		case 0:
			v = unicode.ToLower(v)
		case 1:
			v = unicode.ToUpper(v)
		}
		b.WriteRune(v)
	}
	return b.String()
}

// Mutate randomly mutates a string
func Mutate(a string) string {
	b := []byte(a)
	b[rnd.Intn(len(b))] = byte(rnd.Intn(255)) + 1
	return string(b)
}

func generateTrainingData() []Example {
	files := []string{
		"./data/Generic-BlindSQLi.fuzzdb.txt",
		"./data/Generic-SQLi.txt",
	}

	data := make([]Example, 0)
	for _, file := range files {
		in, err := os.Open(file)
		if err != nil {
			panic(err)
		}
		reader := bufio.NewReader(in)
		lines := make([]string, 0)
		line, err := reader.ReadString('\n')
		for err == nil {
			line = strings.TrimSuffix(line, "\n")
			lines = append(lines, line)
			line, err = reader.ReadString('\n')
		}

		for _, line := range lines {
			if strings.HasPrefix(line, "#") {
				continue
			}
			data = append(data, Example{[]byte(line), true})
			data = append(data, Example{[]byte(strings.ToLower(line)), true})
			data = append(data, Example{[]byte(strings.ToUpper(line)), true})
			for i := 0; i < 10; i++ {
				data = append(data, Example{[]byte(ToMixed(line)), true})
			}
			for i := 0; i < 10; i++ {
				data = append(data, Example{[]byte(Mutate(line)), true})
			}
		}
	}

	length := len(data)
	for i := 0; i < length; i++ {
		size, example := 1+rnd.Intn(16), ""
		for j := 0; j < size; j++ {
			example += string(rune(int('a') + rnd.Intn(int('z'-'a'))))
		}
		data = append(data, Example{[]byte(example), false})
	}

	length = len(data)
	for i := range data {
		j := i + rand.Intn(length-i)
		data[i], data[j] = data[j], data[i]
	}

	return data
}

func main() {
	rnd = rand.New(rand.NewSource(1))
	data := generateTrainingData()
	fmt.Println(len(data))

	validate := data[:1000]
	train := data[1000:]

	networkRnd := rand.New(rand.NewSource(1))
	network := gru.NewGRU(networkRnd)
	for i := 0; i < 10000; i++ {
		example := train[rnd.Intn(len(train))]
		cost := network.Train(example.Data, example.Attack)
		if i%100 == 0 {
			fmt.Println(cost)
		}
	}

	correct, attacks, nattacks := 0, 0, 0
	for i := range validate {
		example := validate[i]
		attack := network.Test(example.Data)
		if example.Attack == attack {
			correct++
		}
		if example.Attack {
			attacks++
		} else {
			nattacks++
		}
	}
	fmt.Println(attacks, nattacks, correct, len(validate))
}

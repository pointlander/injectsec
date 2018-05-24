// Copyright 2018 The InjectSec Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"sort"
	"strings"

	"github.com/pointlander/injectsec/gru"
)

var (
	rnd *rand.Rand
	// FuzzFiles are the files to train on
	FuzzFiles = []string{
		"./data/Generic-BlindSQLi.fuzzdb.txt",
		"./data/Generic-SQLi.txt",
	}
)

// Example is a training example
type Example struct {
	Data   []byte
	Attack bool
}

// Mutate randomly mutates a string
func Mutate(a string) string {
	b := []rune(a)
	switch rnd.Intn(4) {
	case 0:
		prefix := rune(rnd.Intn(255)) + 1
		b = append([]rune{prefix}, b...)
	case 1:
		suffix := rune(rnd.Intn(255)) + 1
		b = append(b, suffix)
	case 2:
		prefix := rune(rnd.Intn(255)) + 1
		suffix := rune(rnd.Intn(255)) + 1
		b = append([]rune{prefix}, b...)
		b = append(b, suffix)
	case 3:
		b[rnd.Intn(len(b))] = rune(rnd.Intn(255)) + 1
	}
	return string(b)
}

func generateTrainingData() []Example {
	data := make([]Example, 0)
	for _, file := range FuzzFiles {
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
			data = append(data, Example{[]byte(strings.ToLower(line)), true})
			for i := 0; i < 64; i++ {
				data = append(data, Example{[]byte(strings.ToLower(Mutate(line))), true})
			}
		}
	}

	length := len(data)
	for i := 0; i < length; i++ {
		size, example := 1+rnd.Intn(16), ""
		for j := 0; j < size; j++ {
			example += string(rune(int('a') + rnd.Intn(int('z'-'a'))))
		}
		data = append(data, Example{[]byte(strings.ToLower(example)), false})
	}

	length = len(data)
	for i := range data {
		j := i + rand.Intn(length-i)
		data[i], data[j] = data[j], data[i]
	}

	return data
}

func printChunks() {
	chunks := make(map[string]int, 0)
	for _, file := range FuzzFiles {
		in, err := os.Open(file)
		if err != nil {
			panic(err)
		}
		reader := bufio.NewReader(in)
		line, err := reader.ReadString('\n')
		for err == nil {
			line = strings.ToLower(strings.TrimSuffix(line, "\n"))
			symbols, buffer := []rune(line), make([]rune, 0, 32)
			for _, v := range symbols {
				if v >= 'a' && v <= 'z' {
					buffer = append(buffer, v)
				} else if len(buffer) > 1 {
					chunks[string(buffer)]++
					buffer = buffer[:0]
				} else {
					buffer = buffer[:0]
				}
			}
			line, err = reader.ReadString('\n')
		}
	}
	type Chunk struct {
		Chunk string
		Count int
	}
	ordered, i := make([]Chunk, len(chunks)), 0
	for k, v := range chunks {
		ordered[i] = Chunk{
			Chunk: k,
			Count: v,
		}
		i++
	}
	sort.Slice(ordered, func(i, j int) bool {
		return ordered[i].Count > ordered[j].Count
	})
	for _, v := range ordered {
		fmt.Println(v)
	}
	fmt.Println(len(chunks))
}

var chunks = flag.Bool("chunks", false, "generate chunks")

func main() {
	flag.Parse()

	if *chunks {
		printChunks()
		return
	}

	rnd = rand.New(rand.NewSource(1))
	data := generateTrainingData()
	fmt.Println(len(data))

	validate := data[:1000]
	train := data[1000:]

	networkRnd := rand.New(rand.NewSource(1))
	network := gru.NewGRU(networkRnd)
	for i := 0; i < 40000; i++ {
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
		} else {
			fmt.Println(string(example.Data), example.Attack, attack)
		}
		if example.Attack {
			attacks++
		} else {
			nattacks++
		}
	}
	fmt.Println(attacks, nattacks, correct, len(validate))
}

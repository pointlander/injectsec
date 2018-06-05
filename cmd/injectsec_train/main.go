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

// Examples are a set of examples
type Examples []Example

// Permute puts the examples into random order
func (e Examples) Permute() {
	length := len(e)
	for i := range e {
		j := i + rand.Intn(length-i)
		e[i], e[j] = e[j], e[i]
	}
}

func generateTrainingData() (training, validation Examples) {
	generators := TrainingDataGenerator(rnd)
	for _, generator := range generators {
		if generator.Make != nil {
			for i := 0; i < 128; i++ {
				line := generator.Make()
				training = append(training, Example{[]byte(strings.ToLower(line)), true})
			}
		}
	}

	var symbols []rune
	for s := 'a'; s <= 'z'; s++ {
		symbols = append(symbols, s)
	}
	for s := '0'; s <= '9'; s++ {
		symbols = append(symbols, s)
	}

	length := len(training)
	for i := 0; i < length; i++ {
		size, example := 1+rnd.Intn(16), ""
		for j := 0; j < size; j++ {
			example += string(symbols[rnd.Intn(len(symbols))])
		}
		training = append(training, Example{[]byte(strings.ToLower(example)), false})
	}

	training.Permute()
	validation = training[:2000]
	training = training[2000:]

	for _, generator := range generators {
		if !generator.Abstract {
			training = append(training, Example{[]byte(strings.ToLower(generator.Form)), true})
		}
	}

	return
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

var (
	chunks = flag.Bool("chunks", false, "generate chunks")
	data   = flag.Bool("data", false, "print training data")
	epochs = flag.Int("epochs", 1, "the number of epochs for training")
)

func main() {
	flag.Parse()
	rnd = rand.New(rand.NewSource(1))

	if *chunks {
		printChunks()
		return
	}

	if *data {
		generators := TrainingDataGenerator(rnd)
		for _, generator := range generators {
			fmt.Println(generator.Form)
			if generator.Make != nil {
				for i := 0; i < 10; i++ {
					fmt.Println(generator.Make())
				}
			}
			fmt.Println()
		}
		return
	}

	os.Mkdir("output", 0744)
	results, err := os.Create("output/results.txt")
	if err != nil {
		panic(err)
	}
	defer results.Close()

	printResults := func(a ...interface{}) {
		s := fmt.Sprint(a...)
		fmt.Println(s)
		results.WriteString(s + "\n")
	}

	training, validation := generateTrainingData()
	fmt.Println(len(training))

	networkRnd := rand.New(rand.NewSource(1))
	network := gru.NewGRU(networkRnd)

	for epoch := 0; epoch < *epochs; epoch++ {
		training.Permute()
		for i, example := range training {
			cost := network.Train(example.Data, example.Attack)
			if i%100 == 0 {
				fmt.Println(cost)
			}
		}

		file := fmt.Sprintf("output/w%v.w", epoch)
		printResults(file)
		err = network.WriteFile(file)
		if err != nil {
			panic(err)
		}

		correct, attacks, nattacks := 0, 0, 0
		for i := range validation {
			example := validation[i]
			attack := network.Test(example.Data)
			if example.Attack == attack {
				correct++
			} else {
				printResults(string(example.Data), example.Attack, attack)
			}
			if example.Attack {
				attacks++
			} else {
				nattacks++
			}
		}
		printResults(attacks, nattacks, correct, len(validation))
	}
}

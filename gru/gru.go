package gru

import (
	"fmt"
	"math/rand"
	"sort"

	G "gorgonia.org/gorgonia"
)

// Chunks are SQL chunks
var Chunks = []string{
	"/*",
	"*/",
	"--",
	"begin",
	"end",
	"set",
	"select",
	"count",
	"top",
	"into",
	"as",
	"from",
	"where",
	"exists",
	"and",
	"&&",
	"or",
	"||",
	"not",
	"in",
	"like",
	"is",
	"between",
	"union",
	"all",
	"having",
	"order",
	"group",
	"by",
	"print",
	"var",
	"char",
	"master",
	"cmdshell",
	"waitfor",
	"delay",
	"time",
	"exec",
	"immediate",
	"declare",
	"sleep",
	"md5",
	"benchmark",
	"load",
	"file",
	"schema",
	"null",
	"version",
}

func init() {
	sort.Slice(Chunks, func(i, j int) bool {
		a, b := Chunks[i], Chunks[j]
		if la, lb := len(a), len(b); la > lb {
			return true
		} else if la == lb {
			return a < b
		}
		return false
	})
}

// GRU is a GRU based anomaly detection engine
type GRU struct {
	*Model
	learner, inference *CharRNN
	attack, nattack    *CharRNN
	solver             G.Solver
	steps              int
}

// NewGRU creates a new GRU anomaly detection engine
func NewGRU(rnd *rand.Rand) *GRU {
	steps := 4
	inputSize := 256 + len(Chunks)
	embeddingSize := 10
	outputSize := 2
	hiddenSizes := []int{5}
	gru := NewModel(rnd, 2, inputSize, embeddingSize, outputSize, hiddenSizes)

	learner := NewCharRNN(gru)
	err := learner.ModeLearn(steps)
	if err != nil {
		panic(err)
	}
	inference := NewCharRNN(gru)
	err = inference.ModeInference()
	if err != nil {
		panic(err)
	}

	attack := NewCharRNN(gru)
	err = attack.ModeLearnLabel(steps, 0)
	if err != nil {
		panic(err)
	}
	nattack := NewCharRNN(gru)
	err = nattack.ModeLearnLabel(steps, 1)
	if err != nil {
		panic(err)
	}

	learnrate := 0.01
	l2reg := 0.000001
	clipVal := 5.0
	solver := G.NewRMSPropSolver(G.WithLearnRate(learnrate), G.WithL2Reg(l2reg), G.WithClip(clipVal))

	return &GRU{
		Model:     gru,
		learner:   learner,
		inference: inference,
		attack:    attack,
		nattack:   nattack,
		solver:    solver,
		steps:     steps,
	}
}

func (g *GRU) convert(input []byte, pad bool) []int {
	length, i := len(input), 0
	data := make([]int, 0, length)
conversion:
	for i < length {
	search:
		for j, v := range Chunks {
			chunk := []byte(v)
			for k, c := range chunk {
				index := i + k
				if index >= len(input) {
					continue search
				}
				if c != input[index] {
					continue search
				}
			}
			data = append(data, 256+j)
			i += len(chunk)
			continue conversion
		}
		data = append(data, int(input[i]))
		i++
	}
	length = len(data)
	if pad {
		for i := 0; i < g.steps-length; i++ {
			data = append(data, ' ')
		}
	}

	return data
}

// Train trains the GRU
func (g *GRU) Train(input []byte, attack bool) float32 {
	data := g.convert(input, true)
	/*label := g.attack
	if !attack {
		label = g.nattack
	}*/
	cost, _, err := g.learner.Learn(data, attack, 0, g.solver)
	//cost, _, err := label.Learn(data, attack, 0, g.solver)
	if err != nil {
		panic(fmt.Sprintf("%+v", err))
	}
	total := 0.0
	for _, v := range cost {
		total += v
	}

	return float32(total) / float32(len(cost))
}

// Test tests a string
func (g *GRU) Test(input []byte) bool {
	data := g.convert(input, false)
	return g.inference.IsAttack(data)
}

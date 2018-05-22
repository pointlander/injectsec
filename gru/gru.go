package gru

import (
	"fmt"
	"math/rand"

	G "gorgonia.org/gorgonia"
)

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
	vocabulary := NewVocabularyFromRange(0, 256)

	inputSize := len(vocabulary.List)
	embeddingSize := 10
	outputSize := 2
	hiddenSizes := []int{5}
	gru := NewModel(rnd, 2, inputSize, embeddingSize, outputSize, hiddenSizes)

	learner := NewCharRNN(gru, vocabulary)
	err := learner.ModeLearn(steps)
	if err != nil {
		panic(err)
	}
	inference := NewCharRNN(gru, vocabulary)
	err = inference.ModeInference()
	if err != nil {
		panic(err)
	}

	attack := NewCharRNN(gru, vocabulary)
	err = attack.ModeLearnLabel(steps, 0)
	if err != nil {
		panic(err)
	}
	nattack := NewCharRNN(gru, vocabulary)
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

// Train trains the GRU
func (g *GRU) Train(input []byte, attack bool) float32 {
	length := len(input)
	data := make([]rune, length)
	for i := range input {
		data[i] = rune(input[i])
	}
	for i := 0; i < g.steps-length; i++ {
		data = append(data, ' ')
	}
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
	length := len(input)
	data := make([]rune, length)
	for i := range input {
		data[i] = rune(input[i])
	}
	return g.inference.IsAttack(data)
}

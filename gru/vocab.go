package gru

const (
	// START is the start symbol
	START rune = 0x02
	// END is the end symbol
	END rune = 0x03
)

// Vocabulary maps between runes and ints
type Vocabulary struct {
	List  []rune
	Index map[rune]int
}

// NewVocabularyFromRange create a new vocabulary list using a range
func NewVocabularyFromRange(start, stop rune) *Vocabulary {
	list, index := make([]rune, 0), make(map[rune]int)
	for i := start; i < stop; i++ {
		list = append(list, i)
	}
	for i, v := range list {
		index[v] = i
	}

	return &Vocabulary{
		List:  list,
		Index: index,
	}
}

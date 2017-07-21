package main

import "fmt"

func main() {
	indexInit()
	//	for i, x := range indices {
	//		fmt.Printf("i\t%d\tx\t%d\t", i, x)
	//		if i%2 == 0 {
	//			fmt.Printf("\n")
	//		}
	//	}

	zeros := make([]uint8, 243)

	ones := make([]uint8, 243)

	for i, _ := range ones {
		ones[i] = 1
	}

	i1 := append(zeros, ones...)

	o1 := Hash(i1)

	c := NewCurl()
	c.Absorb(o1)

	for i := 0; i < 100000; i++ {
		c.Transform()
	}

	x := c.Squeeze()

	fmt.Printf("x: %s\n", tritsToString(x))
	//	fmt.Printf("o1: %s\n", tritsToString(o1))

	//	i2 := append(zeros, zeros...)
	//	i2 = append(i2, ones...)

	//	o2 := Hash(i2)

	//	fmt.Printf("i2: %s\n", tritsToString(i2))
	//	fmt.Printf("o2: %s\n", tritsToString(o2))

}

func tritsToString(in []uint8) string {
	var s string
	for _, x := range in {
		s += fmt.Sprintf("%d", x)
	}
	return s + fmt.Sprintf("\n")
}

/* sBox looks like this:

\  0  1  2 b
  ---------
0| 2  2  0
 |
1| 1  0  2
 |
2| 0  1  1
a

made into a line:

x = 4a+b

x = 0 1 2 3 4 5 6 7 8 9 A
y = 2 2 0 _ 1 0 2 _ 0 1 1


*/

func sBox(a, b uint8) uint8 {
	return box[(a<<2)+b]
}

//constants for Sizes.
const (
	stateSize = 729
	HashSize  = 243
)

var (
	indices [stateSize + 1]int

	box = [11]uint8{2, 2, 0, 5, 1, 0, 2, 5, 0, 1, 1}
)

func indexInit() {
	for i := 0; i < stateSize; i++ {
		p := -365
		if indices[i] < 365 {
			p = 364
		}
		indices[i+1] = indices[i] + p
	}
}

// Curl is a sponge function with an internal state of size StateSize.
// b = r + c, b = StateSize, r = HashSize, c = StateSize - HashSize
type Curl struct {
	state []uint8
}

// NewCurl initializes a new instance with an empty state.
func NewCurl() *Curl {
	c := &Curl{
		state: make([]uint8, stateSize),
	}
	return c
}

//Squeeze do Squeeze in sponge func.
func (c *Curl) Squeeze() []uint8 {
	return c.state[:HashSize]
}

// Absorb fills the internal state of the sponge with the given trits.
func (c *Curl) Absorb(input []uint8) {
	var lenn int
	for i := 0; i < len(input); i += lenn {
		lenn = 243
		if len(input)-i < 243 {
			lenn = len(input) - i
		}
		copy(c.state, input[i:i+lenn])
		c.Transform()
	}
}

// Transform does Transform in sponge func.
func (c *Curl) Transform() {
	var cpy [stateSize]uint8
	for r := 27; r > 0; r-- {
		copy(cpy[:], c.state)
		c.state = c.state[:stateSize]
		for i := 0; i < stateSize; i++ {
			c.state[i] = sBox(cpy[indices[i]], cpy[indices[i+1]])
		}
	}
}

//Hash returns hash of t.
func Hash(t []uint8) []uint8 {
	c := NewCurl()
	c.Absorb(t)
	return c.Squeeze()
}

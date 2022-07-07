package main

type KubesecOutput []struct {
	Object   string  `json:"object"`
	Valid    bool    `json:"valid"`
	FileName string  `json:"fileName"`
	Message  string  `json:"message"`
	Score    int     `json:"score"`
	Scoring  Scoring `json:"scoring"`
}
type Advise struct {
	ID       string `json:"id"`
	Selector string `json:"selector"`
	Reason   string `json:"reason"`
	Points   int    `json:"points"`
}
type Scoring struct {
	Advise []Advise `json:"advise"`
}

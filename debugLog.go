package main

type CircleLog struct {
	Logs [][]byte
	Size int
}

func NewCircleLog(l int) *CircleLog {
	return &CircleLog{
		Logs: make([][]byte, l),
		Size: l,
	}
}

// Write cannot fail
func (L *CircleLog) Write(X []byte) {
	L.Logs = append(L.Logs, X)
}

func (L *CircleLog) Read() (X []byte) {
	X, L.Logs = L.Logs[0], L.Logs[1:]
	return X
}

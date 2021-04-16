package main

import (
	"context"

	log "github.com/sirupsen/logrus"
)

type FailCounter struct {
	StatusCodes chan string
	ctx         context.Context
	cancel      context.CancelFunc
	fails       map[string]int
}

func NewFailCounter() *FailCounter {
	ctx, cancel := context.WithCancel(context.Background())

	f := &FailCounter{
		StatusCodes: make(chan string),
		ctx:         ctx,
		cancel:      cancel,
		fails:       make(map[string]int),
	}

	// start chain checker routine
	go f.countFails()

	return f
}

func (f *FailCounter) finish() {
	close(f.StatusCodes)
	<-f.ctx.Done()
}

func (f *FailCounter) countFails() {
	defer f.cancel()

	for status := range f.StatusCodes {
		count, found := f.fails[status]
		if !found {
			f.fails[status] = 1
		} else {
			f.fails[status] = count + 1
		}
	}

	for status, count := range f.fails {
		log.Errorf("[ %4d ] x %s", count, status)
	}
}

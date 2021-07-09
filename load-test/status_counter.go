package main

import (
	"context"

	log "github.com/sirupsen/logrus"
)

type StatusCounter struct {
	StatusCodes chan string
	ctx         context.Context
	cancel      context.CancelFunc
	statusMap   map[string]int
}

func NewStatusCounter() *StatusCounter {
	ctx, cancel := context.WithCancel(context.Background())

	f := &StatusCounter{
		StatusCodes: make(chan string),
		ctx:         ctx,
		cancel:      cancel,
		statusMap:   make(map[string]int),
	}

	// start chain checker routine
	go f.countStatus()

	return f
}

func (f *StatusCounter) finish() {
	close(f.StatusCodes)
	<-f.ctx.Done()
}

func (f *StatusCounter) countStatus() {
	defer f.cancel()

	for status := range f.StatusCodes {
		f.statusMap[status] += 1
	}

	for status, count := range f.statusMap {
		log.Infof("[ %4d ] x %s", count, status)
	}
}

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/mark-ignacio/bedr/agent/filters"
)

func startFilters(ctx context.Context) (
	<-chan filters.ExecveEvent,
	<-chan filters.OpenEvent,
) {
	execveChan := make(chan filters.ExecveEvent)
	openChan := make(chan filters.OpenEvent)
	execbpf, err := filters.NewExecVEFilter(execveChan, 20)
	if err != nil {
		log.Panicf("error creating ExecVEFilter: %s", err)
		panic(err)
	}
	err = execbpf.Listen(ctx)
	if err != nil {
		log.Panicf("error listening ExecVEFilter: %s", err)
	}
	openbpf, err := filters.NewOpenFilter(openChan)
	if err != nil {
		log.Panicf("error creating OpenFilter: %s", err)
	}
	err = openbpf.Listen(ctx)
	if err != nil {
		log.Panicf("error listening to OpenFilter: %s", err)
	}
	return execveChan, openChan
}

func main() {
	// start it all up
	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()
	execves, opens := startFilters(ctx)
	go func() {
		for event := range execves {
			// TODO: remove personal pollution filter
			if event.Comm == "sendmail" {
				continue
			}
			log.Printf("exeve: %+v", event)
		}
	}()
	go func() {
		// maybe not print it out by default right now
		for event := range opens {
			_ = event
		}
	}()
	// wait until death
	dieSignal := make(chan os.Signal, 1)
	signal.Notify(dieSignal, os.Interrupt, os.Kill)
	fmt.Println("ctrl+c to stop")
	<-dieSignal
}

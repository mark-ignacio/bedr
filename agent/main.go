package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/mark-ignacio/bedr/agent/filters"
)

func startFilters(ctx context.Context) <-chan filters.ExecveEvent {
	execveChan := make(chan filters.ExecveEvent)
	execbpf, err := filters.NewExecVEFilter(execveChan, 20)
	if err != nil {
		panic(err)
	}
	err = execbpf.Listen(ctx)
	if err != nil {
		panic(err)
	}
	return execveChan
}

func main() {
	// start it all up
	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()
	execves := startFilters(ctx)
	go func() {
		for event := range execves {
			log.Printf("%+v", event)
		}
	}()
	// go listenOpen(openChannel)
	// wait until death
	dieSignal := make(chan os.Signal, 1)
	signal.Notify(dieSignal, os.Interrupt, os.Kill)
	fmt.Println("ctrl+c to stop")
	<-dieSignal
}

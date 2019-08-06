package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/mark-ignacio/bedr/agent/filters"
	"github.com/mark-ignacio/bedr/agent/output"
)

func startFilters(ctx context.Context) (
	<-chan filters.ExecveEvent,
	<-chan filters.OpenEvent,
) {
	execveChan := make(chan filters.ExecveEvent, 1000)
	openChan := make(chan filters.OpenEvent, 1000)
	execbpf, err := filters.NewExecVEFilter(execveChan, 20)
	if err != nil {
		log.Panicf("error creating ExecVEFilter: %s", err)
		panic(err)
	}
	err = execbpf.Listen(ctx)
	if err != nil {
		log.Panicf("error listening ExecVEFilter: %s", err)
	}
	// openbpf, err := filters.NewOpenFilter(openChan)
	// if err != nil {
	// 	log.Panicf("error creating OpenFilter: %s", err)
	// }
	// err = openbpf.Listen(ctx)
	// if err != nil {
	// 	log.Panicf("error listening to OpenFilter: %s", err)
	// }
	return execveChan, openChan
}

func main() {
	flagFlush := flag.Int("flush", 100, "max flush/heartbeat threshold")
	flagStdout := flag.Bool("stdout", true, "toggle stdout output")
	// start it all up
	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()
	execves, opens := startFilters(ctx)
	var (
		feedFunc      output.FeedFunc
		heartbeatFunc output.HeartbeatFunc
	)
	if *flagStdout {
		feedFunc = output.StdoutOutput
		heartbeatFunc = output.NoOpHeartbeat
	} else {
		panic("https output not implemented")
	}
	// output and heartbeats
	_ = flagFlush
	go func() {
		lubDub := time.NewTicker(time.Second * 30)
		defer lubDub.Stop()
		for {
			// emit something, anything!
			select {
			case execve := <-execves:
				feedFunc(&execve)
			case open := <-opens:
				feedFunc(&open)
			case <-lubDub.C:
				heartbeatFunc()
			}
		}
	}()
	// wait until death
	dieSignal := make(chan os.Signal, 1)
	signal.Notify(dieSignal, os.Interrupt, os.Kill)
	fmt.Println("ctrl+c to stop")
	<-dieSignal
}

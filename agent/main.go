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

func listenExecve(ctx context.Context) <-chan filters.ExecveEvent {
	execveChan := make(chan filters.ExecveEvent, 1000)
	execbpf, err := filters.NewExecVEFilter(execveChan, 20)
	if err != nil {
		log.Panicf("error creating ExecVEFilter: %s", err)
		panic(err)
	}
	err = execbpf.Listen(ctx)
	if err != nil {
		log.Panicf("error listening ExecVEFilter: %s", err)
	}
	return execveChan
}

func listenOpen(ctx context.Context) <-chan filters.OpenEvent {
	openChan := make(chan filters.OpenEvent, 1000)
	openbpf, err := filters.NewOpenFilter(openChan)
	if err != nil {
		log.Panicf("error creating OpenFilter: %s", err)
	}
	err = openbpf.Listen(ctx)
	if err != nil {
		log.Panicf("error listening to OpenFilter: %s", err)
	}
	return openChan
}

func listenConnect(ctx context.Context) <-chan filters.ConnectEvent {
	connectChan := make(chan filters.ConnectEvent, 1000)
	openbpf, err := filters.NewConnectFilter(connectChan)
	if err != nil {
		log.Panicf("error creating ConnectFilter: %s", err)
	}
	err = openbpf.Listen(ctx)
	if err != nil {
		log.Panicf("error listening to ConnectFilter: %s", err)
	}
	return connectChan
}

func startFilters(ctx context.Context, only string) (
	execveChan <-chan filters.ExecveEvent,
	openChan <-chan filters.OpenEvent,
	connectChan <-chan filters.ConnectEvent,
) {
	log.Printf("only: %s", only)
	switch only {
	case "execve":
		execveChan = listenExecve(ctx)
	case "open":
		openChan = listenOpen(ctx)
	case "connect":
		connectChan = listenConnect(ctx)
	case "":
		execveChan = listenExecve(ctx)
		openChan = listenOpen(ctx)
		connectChan = listenConnect(ctx)
	default:
		log.Fatalf("unknown 'only' option: '%s'", only)
	}
	return
}

func main() {
	flagFlush := flag.Int("flush", 100, "max flush/heartbeat threshold")
	flagStdout := flag.Bool("stdout", false, "toggle stdout output")
	flagOnly := flag.String("only", "", "only listen to a certain syscall")
	flag.Parse()
	// start it all up
	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()
	execves, opens, connects := startFilters(ctx, *flagOnly)
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
			case connect := <-connects:
				feedFunc(&connect)
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

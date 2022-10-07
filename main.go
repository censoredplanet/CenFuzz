package main

import (
	"log"
	"sync"

	"github.com/censoredplanet/CenFuzz/config"
	"github.com/censoredplanet/CenFuzz/util"
	"github.com/censoredplanet/CenFuzz/worker"
)

func WorkerType() worker.Worker {

	switch config.Protocol {
	case "https":
		return &worker.HTTPSWorker{}
	case "http":
		return &worker.HTTPWorker{}
	default:
		panic("unknown protocol")
	}

}

func main() {
	w := WorkerType()
	log.Printf("Starting HTTP(S) fuzzers")
	inputs := util.ParseInfile(config.Infile)
	uncensoredKeyword := config.UncensoredKeyword
	outfile := config.Outfile

	ResultsQueue := make(chan *util.Result)
	workerdoneChan := make(chan bool)
	resultsdoneChan := make(chan bool)

	workQueue := make(chan interface{})

	fuzzerList := util.ParseFuzzerInfile(config.FuzzerInFile)
	fuzzerObjects := w.FuzzerObjects(fuzzerList)

	var workWG sync.WaitGroup
	for i := 0; i < config.NumWorkers; i++ {
		go w.Worker(workQueue, ResultsQueue, uncensoredKeyword, &workWG, workerdoneChan)
	}
	log.Printf("Workers spawned")

	go util.SaveResults(ResultsQueue, outfile, resultsdoneChan)
	log.Printf("Output routine started")

	for _, input := range inputs {
		vp := input.VP
		vp.Mu.Lock()
		work := w.Work(input.VP.IP, input.Domain, fuzzerObjects)
		workWG.Add(1)
		workQueue <- work
		log.Println("Assigned work to VP: ", input.VP.IP)
		vp.Mu.Unlock()
	}
	close(workQueue)
	log.Println("All work assigned. Waiting for workers to return")
	workWG.Wait()
	<-workerdoneChan
	log.Println("Waiting for results to be written")
	close(ResultsQueue)
	<-resultsdoneChan

}

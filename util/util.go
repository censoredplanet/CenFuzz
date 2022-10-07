package util

import (
	"bufio"
	"encoding/json"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/censoredplanet/CenFuzz/config"
)

type VantagePoint struct {
	IP string
	Mu sync.Mutex
}

type Input struct {
	//Vantage Point IP
	VP *VantagePoint
	//Domain or Keyword to test for censorship
	Domain string
}

type Result struct {
	IP                    string      `json:"IP"`
	Domain                string      `json:"Domain"`
	TestName              string      `json:"TestName"`
	IsNormal              bool        `json:"IsNormal"`
	MatchesNormal         bool        `json:"MatchesNormal"`
	MatchesUncensored     bool        `json:"MatchesUncensored"`
	NormalDifferences     string      `json:"NormalDifferences"`
	UncensoredDifferences string      `json:"UncensoredDifferences"`
	Request               interface{} `json:"Request"`
	Response              interface{} `json:"Response"`
	Error                 interface{} `json:"Error"`
	UncensoredRequest     interface{} `json:"UncensoredRequest"`
	UncensoredResponse    interface{} `json:"UncensoredResponse"`
	UncensoredError       interface{} `json:"UncensoredError"`
	StartTime             time.Time   `json:"StartTime"`
	EndTime               time.Time   `json:"EndTime"`
}

type TLSdata struct {
	Version                    uint16
	HandshakeComplete          bool
	CipherSuite                uint16
	NegotiatedProtocol         string
	NegotiatedProtocolIsMutual bool
	PeerCertificates           []byte
	ServerName                 string
	HTTPResponse               interface{}
}

func CreateFile(path string) *os.File {
	if path == "-" || path == "" {
		return os.Stdout
	}
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0755)
	if err != nil {
		log.Fatal(err)
	}
	return file
}

func OpenFileforRead(path string) *os.File {
	infile, err := os.OpenFile(path, os.O_RDONLY, 0444)
	if err != nil {
		log.Fatal(err)
	}
	return infile
}

func SaveResults(Results <-chan *Result, outfile string, done chan<- bool) {
	resultsFile := CreateFile(outfile)
	for result := range Results {
		data, err := json.Marshal(result)
		if err != nil {
			log.Println(err.Error())
			continue
		}
		data = append(data, byte('\n'))
		n, err := resultsFile.Write(data)
		if err != nil || n != len(data) {
			log.Println(err.Error())
		}
	}
	done <- true

}

func Sleep(err interface{}) time.Duration {
	if err != nil {
		//If there is an error, there is a possibility that this could be network interference or at least some temporary network loss. So we should wait for more time
		return config.StatefulDelay
	}

	return config.FuzzDelay
}

func ParseInfile(path string) []*Input {
	infile := OpenFileforRead(path)
	scanner := bufio.NewScanner(infile)
	var inputs []*Input
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ",")
		vp := &VantagePoint{IP: parts[0]}
		inputs = append(inputs, &Input{
			VP:     vp,
			Domain: parts[1],
		})
	}
	return inputs
}

type FuzzerInput struct {
	FuzzerNumber int
	All          bool
}

func ParseFuzzerInfile(path string) []*FuzzerInput {
	infile := OpenFileforRead(path)
	scanner := bufio.NewScanner(infile)
	var fuzzers []*FuzzerInput
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ",")
		fuzzerNumber, err := strconv.Atoi(parts[0])
		if err != nil {
			log.Fatal(err)
		}
		all := false
		if len(parts) > 1 {
			all, err = strconv.ParseBool(parts[1])
			if err != nil {
				log.Fatal(err)
			}
		} else {
			all = config.All
		}
		fuzzers = append(fuzzers, &FuzzerInput{
			FuzzerNumber: fuzzerNumber,
			All:          all,
		})
	}

	return fuzzers
}

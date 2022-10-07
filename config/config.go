package config

import (
	"flag"
	"time"

	"os"
)

var StatefulDelay time.Duration
var FuzzDelay time.Duration
var Infile string
var FuzzerInFile string
var Outfile string
var UncensoredKeyword string
var Protocol string
var NumberOfProbesPerTest int
var All bool
var NumWorkers int
var Iface string
var Srcip string
var Dir string
var AnalyzeOutfile string
var RouteviewsFile string
var MaxmindFile string
var Bigquery bool
var BigqueryProjectID string
var BigqueryDatasetID string
var BigqueryTableID string

func init() {
	//Fuzz config
	statefulDelay := 100
	fuzzDelay := 5
	flag.StringVar(&Infile, "infile", "", "File in which to read input from (required) - Must have lines in the form (vantage point ip, domain to send)")
	flag.StringVar(&FuzzerInFile, "fuzzer-infile", "", "File which specifies the fuzzers to run (required). Each line must have fuzzer ID. Optionally, each line may also include (Comma-separated) a 'True' or 'False' value. A 'True' value indicates running all possible permutations for that fuzzer. A 'False' value indicates running random fuzzing values for that fuzzer.")
	flag.StringVar(&Outfile, "outfile", "-", "File in which to write output (default stdout)")
	flag.StringVar(&UncensoredKeyword, "uncensored", "example.com", "Uncensored Keyword")
	flag.IntVar(&NumWorkers, "num-workers", 1, "Number of parallel workers to run for measurements")
	flag.IntVar(&fuzzDelay, "fuzz-delay", 5, "number of seconds to wait between each request per strategy when there is no stateful blocking observed")
	flag.IntVar(&statefulDelay, "stateful-delay", 100, "number of seconds to wait between each request when there is some stateful blocking observed")
	flag.StringVar(&Protocol, "protocol", "http", "HTTPS or HTTP fuzzing. Default - HTTP")
	flag.BoolVar(&All, "all", false, "If true, try all possible permutations for fuzzer values where applicable. If false, choose a set of random fuzzing values for all fuzzers. Default - False")
	flag.StringVar(&Iface, "iface", "", "Interface to send measurements on")
	flag.StringVar(&Srcip, "srcip", "", "Source IP to send measurements from")
	flag.IntVar(&NumberOfProbesPerTest, "numprobes", 3, "Number of random requests to send per test (default 3)")

	//Analyze config
	flag.StringVar(&Dir, "analyze-dir", "", "Directory with fuzz files (required)")
	flag.StringVar(&RouteviewsFile, "routeviews-file", "-", "Routeviews File (required)")
	flag.StringVar(&MaxmindFile, "mmdb-file", "-", "Maxmind MMDB File (required)")
	flag.StringVar(&AnalyzeOutfile, "analyze-outfile", "-", "File to write analyzed fuzzing data")
	flag.BoolVar(&Bigquery, "bigquery", false, "If true, upload data to table in bigquery")
	flag.StringVar(&BigqueryProjectID, "bigquery-project", "-", "Bigquery project ID")
	flag.StringVar(&BigqueryDatasetID, "bigquery-dataset", "-", "Bigquery dataset ID")
	flag.StringVar(&BigqueryTableID, "bigquery-table", "-", "Bigquery table ID")
	flag.Parse()

	// As of now, two input files are both required.
	if (len(Infile) == 0 || len(FuzzerInFile) == 0) && len(Dir) == 0 {
		flag.PrintDefaults()
		os.Exit(1)
	}
	FuzzDelay = time.Duration(fuzzDelay) * time.Second
	StatefulDelay = time.Duration(statefulDelay) * time.Second
}

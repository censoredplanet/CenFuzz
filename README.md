# CenFuzz
[![Build Status](https://github.com/censoredplanet/CenFuzz/workflows/CenFuzz/badge.svg)](https://github.com/censoredplanet/CenFuzz/actions)
[![DOI](https://zenodo.org/badge/547397275.svg)](https://zenodo.org/badge/latestdoi/547397275)


*Are you using `CenFuzz`? If so, let us know! Shoot us an email at censoredplanet@umich.edu.*

`CenFuzz` is a deterministic censorship and middlebox fuzzing tool that performs application-layer fuzzing strategies on blocked connections such that the same strategies are performed across all tested devices. `CenFuzz` performs several modifications to the HTTP GET Request and the TLS Client Hello packets, based on the grammars of these protocols. See below and the `http_fuzzer/` and `https_fuzzer` directories for a set of deterministic fuzzers for each protocol. For more information, refer to [our paper](https://ramakrishnansr.org/publications). 

The following HTTP fuzzers are provided (for example domain `example.com`). 

| HTTP Fuzzer ID |          HTTP Fuzzer         |              Fuzzer Operation             |         Example        | Total No. of Permutations | 
| -------------- | ---------------------------- | ----------------------------------------- | ---------------------- | ------------------------- |
|       1        | Hostname Padding             | Padding `*` characters to hostname        | **example.com*         |              9            |
|       2        | Get Word Capitalize          | Capitalize parts of the GET word          | GeT                    |              8            |
|       3        | Get Word Remove              | Remove parts of the GET word              | Ge                     |              7            |
|       4        | Get Word Alternate           | Use a different HTTP method               | POST                   |              6            |
|       5        | Http Word Capitalize         | Capitalize parts of the http word         | HtTP/1.1               |              16           |
|       6        | Http Word Remove             | Remove parts of the http word             | HTP/1.1                |              167          |
|       7        | HttP Word Alternate          | Use alternates in place of http word      | XXXX/1.1               |              16           |
|       8        | Host Word Capitalize         | Capitalize parts of the Host word         | HoST:                  |              16           |
|       9        | Host Word Remove             | Remove parts of the Host word             | ost:                   |              63           |
|       10       | Host Word Alternate          | Use alternates in place of Host word      | HostHeader:            |              7            |
|       11       | Http Delimiter Word Remove   | Remove parts of the http delimiters       | \r                     |              3            |
|       12       | Path Alternate               | Use alternate path other than `/`         | ?                      |              8            |
|       13       | Header Alternate             | Add custom HTTP header to request         | Connection: keep-alive |              59           |
|       14       | HostName Alternate           | Repeat or modify domains in certain ways  | ""                     |              5            |
|       15       | Hostname TLD Alternate       | Provide different TLD to domain           | example.net            |              10           |
|       16       | Hostname Subdomain Alternate | Provide different subdomain               | mail.example.net       |              10           |
|       17       | Hostname Long Padding        | Padding space characters to hostname      |           example.com  |              27           |

The following HTTPS fuzzers are provided (for example domain `example.com`). 

| HTTPS Fuzzer ID |         HTTPS Fuzzer         |              Fuzzer Operation             |         Example        | Total No. of Permutations | 
| --------------- | ---------------------------- | ----------------------------------------- | ---------------------- | ------------------------- |
|       1         | SNI Padding                  | Padding `*` characters to SNI             | **example.com*         |              9            |
|       2         | Min Version Alternate        | Use a different minimum TLS version       | TLS 1.1                |              4            |
|       3         | Max Version Alternate        | Use a different maximum TLS version       | TLS 1.1                |              4            |
|       4         | CipherSuite Alternate        | Use a different ciphersuite               | TLS_AES_128_GCM_SHA256 |              25           |
|       5         | Client Certificate Alternate | Use a different client certificate        | CN=www.test.com        |              3            |
|       6         | SNI Alternate                | Repeat or modify domains in certain ways  | " "                    |              4            |
|       7         | SNI TLD Alternate            | Provide different TLD to domain           | example.org            |              10           |
|       8         | SNI Subdomain Alternate      | Provide different subdomain               | wiki.example.net       |              10           |
|       9         | SNI Long Padding             | Padding space characters to SNI           |           example.com  |              27           |


## Installation
- Install go version 1.13 or newer see <https://github.com/golang/go/wiki/Ubuntu>
- Run `go get github.com/censoredplanet/CenFuzz`.
- Run `go get` and `go build` once inside the directory. 

## Configuration
The following flags can be provided for running measurements:

|         Flag           |          Default         |                       Function                               |                  Example                   |
| ---------------------- | ------------------------ | ------------------------------------------------------------ | ------------------------------------------ |
| infile                 | Required                 | A csv file with `endpoint, domain` pairs to measure          | `examples/input.csv`                       |
| fuzzer-infile          | Required                 | A csv file with `Fuzzer ID, All permutations? boolean`       | `examples/http-fuzz-input.csv`             |
| outfile                | stdout                   | File to write output in                                      | `examples/example_direct_http_fuzz.json`   |
| uncensored             | example.com              | Control keyword which is not blocked                         |                                            |
| num-workers            | 1                        | Number of workers to run measurements parallely              |                                            |
| fuzz-delay             | 5                        | Number of seconds between unblocked measurements             |                                            |
| stateful-delay         | 120                      | Number of seconds between blocked measurements               |                                            |
| protocol               | http                     | HTTP or HTTPS protocol                                       |                                            |
| All                    | false                    | If true, run all permutations                                |                                            |
| iface                  | ""                       | Network interface to use to run measurements                 |                                            |
| srcip                  | ""                       | Select source IP address to use (can be used to spoof)       |                                            |
| numprobes              | 3                        | No. of permutations per strategy in case All = false         |                                            |
| randomized             | false                    | Randomizes order of extensions and ciphersuites (HTTPS only) |                                            |

The following flags can be provided for analyzing measurements:
|         Flag           |          Default         |                       Function                         |           Example             |
| ---------------------- | ------------------------ | ------------------------------------------------------ | ----------------------------- |
| analyze-dir            | Required                 | Directory with fuzzing measurement output (*_fuzz.json)|                               |
| infile                 | Required                 | [Blockpage signature patterns](https://assets.censoredplanet.org/blockpage_signatures.json)                   |                               |
| routeviews-file        | Required                 | Data from Routeviews to get ASN information            |                               |
| mmdb-file              | Required                 | Maxmind mmdb file                                      |                               |
| analyze-outfile        | stdout                   | File to write analyzed output in                       | `examples/analyzed.json`      |
| bigquery               | false                    | If true, upload to table in Bigquery                   |                               |
| bigquery-project       | -                        | Bigquery project ID                                    |                               |
| bigquery-dataset       | -                        | Bigquery dataset ID                                    |                               |
| bigquery-table         | -                        | Bigquery table ID                                      |                               |


## Usage
The `CenFuzz` tool provides two functions:
1. Run fuzzing measurements across a list of endpoints: 
```
./CenFuzz --infile examples/input.csv --fuzzer-infile examples/http-fuzz-input.csv --outfile examples/example_direct_http_fuzz.json --num-workers 2 --fuzz-delay 10 --stateful-delay 120 --protocol http --iface enp1s0f0
```
2. Analyze data:
 ```
 go run cmd/analyze/analyze.go --analyze-dir examples --routeviews-file routeviews_file --mmdb-file mmdb_file --analyze-outfile examples/analyzed.json --infile blockpage_signatures.json
 ```

## Disclaimer
Russing `CenFuzz` from your machine may place you at risk if you use it within a highly censoring regime. `CenFuzz` takes actions that try to trigger censoring middleboxes multiple times, and try to interfere with the functioning of the middlebox. Therefore, please exercice caution while using the tool, and understand the risks of running `CenFuzz` before using it on your machine. Please refer to [our paper](https://ramakrishnansr.org/publications) for more information. 

## Data
The fuzzing measurement data from the study in [our paper](https://ramakrishnansr.org/publications) can be found [here](https://drive.google.com/file/d/1begpJRkNfI8Rg378A1S0BQKVYrWFfuSa/view?usp=sharing). 

## Citation
If you use the `CenFuzz` tool or data, please cite the following publication:
```
@inproceedings{sundararaman2022network,<br>
title = {Network Measurement Methods for Locating and Examining Censorship Devices},<br>
author = {Sundara Raman, Ram and Wang, Mona and Dalek, Jakub and Mayer, Jonathan and Ensafi, Roya},<br>
booktitle={In ACM International Conference on emerging Networking EXperiments and Technologies (CoNEXT)},<br>
year={2022}
```

## Contributing
`CenFuzz` currently implements a small set of fuzzing strategies, and we need the help of the community to improve `CenFuzz` and keep it updated! We welcome any and all contributions. Please feel free to open an Issue, Pull Request, or send us an email.

To simply add a new fuzzing strategy, the following changes would have to be made: 

1. Create an `Init()` and `Fuzz()` in a new Golang file inside the `http_fuzzer` or `https_fuzzer` directories. These two functions are required as they are interfaces, and the main logic of the strategy should be initiated inside the `Init()` function. See the strategies already implemented for examples. 

2. Make the appropriate changes inside `http_fuzzer/fuzzer.go` or `https_fuzzer/fuzzer.go` if your strategy requires runtime computations, as the requests are computed here. 

3. Add a new incrementing Fuzzer ID for your strategy and create the mapping inside `worker/http_worker.go` or `worker/https_Worker.go`. 

4. Run, Test, and Enjoy! 

## Licensing
This repository is released under the GNU General Public License (see [`LICENSE`](LICENSE)).

## Contact
Email addresses: `censoredplanet@umich.edu`, `ramaks@umich.edu`, `monaw@princeton.edu`, `jakub@citizenlab.ca`, `jonathan.mayer@princeton.edu`, and `ensafi@umich.edu`

## Contributors

[Ram Sundara Raman](https://github.com/ramakrishnansr)

[Mona Wang](https://github.com/m0namon)

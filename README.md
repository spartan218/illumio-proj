# Flow Log Parser

This project processes network flow logs by tagging traffic based on a lookup table and counting occurrences. The results are saved in a CSV file.

## Features
- Supports v2 of flow-log-records
  - https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html
- Parses flow logs from a specified file
- Matches traffic to tags using a lookup table
- Counts tag occurrences and port/protocol combinations
- Outputs the results to a CSV file

## Requirements
- Python 3.x

## Running the Code
To execute the script and process flow logs, run:
```sh
python3 log_parser.py
```
The script processes logs using a lookup table and saves results in `resources/output.csv`.

## Running Tests
Unit tests ensure the correctness of log parsing and output generation. Run tests with:
```sh
python3 -m unittest test_flow_logs.py
```
Tests cover:
- Lookup table loading
- Flow log parsing
- Output file correctness

## File Structure
```
.
├── main.py                 # Main script to process flow logs
├── test_flow_logs.py       # Unit tests for the parser
├── resources/
│   ├── lookup_table        # Lookup table file
│   ├── raw_logs            # Raw flow logs file
│   ├── output.csv          # Generated output file
└── README.md               # Project documentation
```


## Considerations

1. Only in memory data structures were used to limit imports dependencies
2. For 10MB files we are parsing the files line by line rather than loading the entire file into memory
3. Mappings naturally seem like a data structure to be persisted
4. iana_protocols are hard coded, but we could use an external library to translate codes to protocols
5. I believe that some of the output examples given in the email (in the ProjectRequirements.txt) are incorrect 
6. the sample file (Sample flow logs) is missing a port 22 entry but the example output has a port 22 tag count
- sv_P4,1 (notice this maps to 22,tcp,sv_P4 )
- the (Count of matches for each port/protocol combination) does not account for some of the port/protocols in the example that is present

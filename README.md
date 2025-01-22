# PCAP-dataExtractor
Python code to parse JSON network traffic data to CSV file. 

Note: The script is written for Python 3.6.7. Probably ork with all other versions.
Steps for PCAP -> JSON -> Parsed data file.

Step 1: Export pcap data to JSON file.

Wireshark has a feature to export it's capture files to JSON.
File->Export Packet Dissections->As JSON

Step 2: Make required changes in json2csv.py file.

Step 3: Execute json2pcap.py 

<!-- TODO Update the text above -->

## Notes

### Regarding the implementations

The older version (e.g. on [this commit](https://github.com/oliveiraleo/PCAP-dataExtractor/blob/a6d697ed9eff5fbc10d9831ad1b31af76d8aee3a/json2csv.py) or even [the original one](https://github.com/abhiverma866/PCAP-dataExtractor)) of the code may be used after adapting the column labels to the new environment

The current version was designed to be used as a Python module, however changes might be also required to adapt to your input files

### Creating the JSON files

Wireshark has a feature to export PCAP capture files to JSON. Navigate through the menus listed below:

`File -> Export Packet Dissections -> As JSON ...`

Or you can use tshark for that:

```
tshark -r input.pcap -T json > output.json"
```

### Tested software environment

Python 3.13.1 (may work with older versions too)
Pandas 2.2.3

## Usage

To use in stand alone mode, clone the repository, uncomment the last line of python file and install the requirements

Or import it (e.g. `from json2csv import parse`)

## License

This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the [GNU Affero General Public License](https://www.gnu.org/licenses/agpl-3.0.html) for more details.

You should have received [a copy of the GNU Affero General Public License](./LICENSE) along with this program. If not, see <https://www.gnu.org/licenses/>.

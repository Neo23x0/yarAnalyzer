# yarAnalyzer
Yara Rule Analyzer and Statistics

# Description
yarAnalyzer creates statistics on a yara rule set and files in a sample directory. Place some signatures with .yar extension in the "signatures" folder and then run yarAnalyzer on a certain sample directory like:

```yarAnalyzer.py -p /sample/path```

It will generate two tables as command line output and two CSV files. 

# Screenshots

Rule Statistics

![Rule Statistics](/screens/screen1.png)

File Statistics

![File Statistics](/screens/screen2.png)

CSV Output in Excel

![CSV Output in Excel](/screens/screen3.png)

# Usage

```
usage: yarAnalyzer.py [-h] -p path [-i identifier] [-m max-size]
                      [-l max-string] [-f first-bytes] [--noempty]
                      [--printAll] [--debug]

yarAnalyzer - Yara Rules Statistics and Analysis

optional arguments:
  -h, --help      show this help message and exit
  -p path         Path to scan
  -i identifier   Set an identifier - will be used in filename
                  identifier_rule_stats.csv and identifier_file_stats.csv
  -m max-size     Max file size in MB (default=10)
  -l max-string   Max filename/rulename string length in command line output
  -f first-bytes  Number of first bytes to show in output
  --noempty       Don't show empty values
  --printAll      Print all files that are scanned
  --debug         Debug output
  
```


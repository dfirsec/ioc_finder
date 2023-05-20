# IOC Finder

![Generic badge](https://img.shields.io/badge/python-3.9-blue.svg)

Quick and dirty method to search for filenames that match IOCs if hashes are not yet available.

## Description

IOC Finder is a Python script that allows you to search for filenames that match Indicators of Compromise (IOCs). It is a quick and simple method to identify potential matches between IOCs and filenames when hashes are not yet available.

The script supports two modes of operation:
- **IOC Mode**: Search for IOCs in a given drive path or directory.
- **File Mode**: Process a file containing IOCs and search for matches in a drive path or directory.

The search can be performed on partial or exact matches depending on the provided options.

## Features

- Search for filenames that match IOCs
- Support for partial or exact match search
- Generate a CSV file with the matched filenames and related information
- Display the results in a table format in the console

## Requirements

- Python 3.9 or higher
- Windows operating system

## Installation

1. Clone the repository:

```text
git clone https://github.com/dfirsec/ioc_finder.git
```

2. Navigate to the project directory:

```text
cd ioc_finder
```

3. Install the required dependencies using poetry:

```text
poetry install
```

## Usage

IOC Finder can be run using the following command:

```text
python ioc_finder.py [options] path
```

The available options are:

`-c`: Search for filenames that contain the IOC string (partial match).
> The *-c* option is used in conjunction with the *-i* option as a wildcard match (\*) for anything before and after the string, e.g, searching for 'bad' would yield 'one**bad**apple', 'one**bad**fruit', 'ihave**bad**taste', etc, and also ignores the string case.

`-i` \<ioc1>, \<ioc2> ...: Specify one or more IOCs to search for. Use commas or spaces to separate multiple IOCs.  
> This option uses a wildcard match (\*) for anything after the end of the string, e.g, searching for 'bad' would yield '**bad**apple', '**bad**fruit', '**bad**taste', etc.  Matches are case insensitive.

`-f`: Use the "known_iocs.txt" file containing IOCs to search for matches.
> The *-f* option is when you need to search for many filenames. It's currently limited to exact filename matching, however, it's case insensitive.

Add your IOC filenames to the *'known_iocs.txt'* text file.
```text
# ADD IOC FILENAMES BELOW THIS LINE
badstuff.txt
badexe.exe
Xdggrphr.lnk
lookhere.dll
```

The `path` argument should be the path to the directory or drive you want to scan.

## Examples

Search for filenames that contain the IOC string "bad" in the "c:\" directory:

```text
python ioc_finder.py c:\ -i bad
```

Adding a '.' to the end of the string will return the string + any extension.

```text
python ioc_finder.py c:\ -i bad.
+------------------------------------------|+---------+------------+----------------------------------+
| File name                                |    Size  | Created    | Hash                             |
+------------------------------------------|+---------+------------+----------------------------------+
| c:\Program Files\Microsoft\bad.exe       |  120214  | 2018-12-21 | 34d70beb5434t4rgfvbd73799b50d125 |
| c:\Windows\bad.txt                       |     670  | 2019-02-29 | cd5bc2aaed4c6brjyth1eabcf34285de |
| c:\Windows\bad.lnk                       |     429  | 2018-02-15 | 500758431b795b776e4erdfwed700cef |
+------------------------------------------+----------+------------+----------------------------------+
```

Search for filenames that contain a wildcard match for anything before and after the IOC string IOC "bad" in the "c:\data" directory:

```text
python ioc_finder.py c:\data -c -i bad
```

Search for specific IOCs "virus", "trojan", and "spyware" in the "D:\docs" directory:

```text
python ioc_finder.py -i virus,trojan,spyware D:\docs
```

Search for IOCs using the "known_iocs.txt" file in the "E:\files" directory:

```text
python ioc_finder.py -f E:\files
```

## Output

IOC Finder generates a CSV file in the "results" folder with the matched filenames and related information. The CSV file is named with the format "hostname_timestamp.csv", where "hostname" is the name of the current machine and "timestamp" is the date and time when the script was executed.

The results are also displayed in a table format in the console.

### Example run...

```text
python ioc_finder.py c:\ -f
> Searching for IOCs on SYS-NAME: 38934 files [00:08, 4794.81 files/s]

✔ Found 2 IOCs on SYS-NAME
    --> Results saved to results\SYS-NAME_20200220-203455.csv
```

Results are saved to a file and presented with the name, size, creation date, and hash:

```text
+------------------------------------------|+---------+------------+----------------------------------+
| File name                                |    Size  | Created    | Hash                             |
+------------------------------------------|+---------+------------+----------------------------------+
| c:\Program Files\Microsoft\badexe.exe    |  140288  | 2018-12-20 | 34d70beb5434c95bd73799b55ea0d125 |
| c:\Windows\badstuff.txt                  |     470  | 2019-08-23 | cd5bc2aaed4c6b8a21eabcf34285d69e |
| c:\Windows\Xdggrphr.lnk                  |     462  | 2019-08-23 | 5007584931b795b776e6b15f4d700cef |
| c:\Windows\lookhere.dll                  |    6836  | 2019-08-23 | 68baa20566a1afa2319e6afc5942e056 |
+------------------------------------------+----------+------------+----------------------------------+
```

## Contributing

Contributions are welcome! If you find any issues or have suggestions for improvement, please create an issue or submit a pull request.

## License
This project is licensed under the MIT License.
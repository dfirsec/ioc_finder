# IOC Finder

![Generic badge](https://img.shields.io/badge/python-3.7-blue.svg) [![Twitter](https://img.shields.io/badge/Twitter-@pulsecode-blue.svg)](https://twitter.com/pulsecode)

```ioc_finder.py``` Quick and dirty method to search for filenames that match IOCs if file hashes are not yet available.
                    A more comprehensive method would be to use Yara.

```console

          ________  ______   _______           __
         /  _/ __ \/ ____/  / ____(_)___  ____/ /__  _____
         / // / / / /      / /_  / / __ \/ __  / _ \/ ___/
       _/ // /_/ / /___   / __/ / / / / / /_/ /  __/ /
      /___/\____/\____/  /_/   /_/_/ /_/\__,_/\___/_/

usage: ioc_finder.py [-h] [-c] (-i  [...] | -f) path

positional arguments:
  path        Path to search

options:
  -h, --help  show this help message and exit
  -c          ioc name contains string
  -i  [ ...]  single or list of iocs (comma separated)
  -f          use known_iocs.txt file containing iocs
```

## Installation

```text
git clone https://github.com/dfirsec/ioc_finder.git
cd ioc_finder
pip install -r requirements.txt
```

## Options

### -i option

```text
python ioc_finder.py c:\ -i bad
> Searching for IOCs on SYS-NAME: 38934 files [00:08, 4794.81 files/s]

✔ Found 2 IOCs on SYS-NAME
    --> Results saved to results\SYS-NAME_20200220-203455.csv
```

The *-i* option uses a wildcard match (\*) for anything after the end of the string, e.g, searching for 'bad' would yield '**bad**apple', '**bad**fruit', '**bad**taste', etc, and also ignores the string case.

You can also search using a list of items (comma/space separated):
```python ioc_finder.py c:\ -i bad, pizza, cheese, apple```

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

### -c option

```text
python ioc_finder.py c:\ -c -i bad
> Searching for IOCs on SYS-NAME: 38934 files [00:08, 4794.81 files/s]
```

The *-c* option is used in conjunction with the *-i* option as a wildcard match (\*) for anything before and after the string, e.g, searching for 'bad' would yield 'one**bad**apple', 'one**bad**fruit', 'ihave**bad**taste', etc, and also ignores the string case.

### -f option

The *-f* option is when you need to search for many filenames. It's currently limited to exact filename matching, however, it's case insensitive (will match upper and lower).

Add your IOC filenames to the *'known_iocs.txt'* text file.

```text
# ADD IOC FILENAMES BELOW THIS LINE
badstuff.txt
badexe.exe
Xdggrphr.lnk
lookhere.dll
```

Example run...

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

import csv
import hashlib
import os
import socket
import sys
import time
from argparse import ArgumentParser
from datetime import datetime
from pathlib import Path

from colorama import Back, Fore, Style, init
from tqdm import tqdm
from wcmatch import fnmatch

__author__ = "DFIRSec (@pulsecode)"
__version__ = "0.0.2"
__description__ = "Quick and dirty method to search for filenames that match IOCs if hashes are not yet available."


class Workers(object):
    def __init__(self, count=None):
        self.count = count

    filepath = Path(__file__).parent
    results = filepath / 'results'
    iocs = filepath / 'iocs'
    hostname = socket.gethostname().upper()

    # Unicode Symbols and colors -  ref: http://www.fileformat.info/info/unicode/char/a.htm
    processing = f'{Fore.CYAN}\u2BA9{Fore.RESET}'
    found = f'{Fore.GREEN}\u2714{Fore.RESET}'
    notfound = f'{Fore.YELLOW}\u00D8{Fore.RESET}'
    error = f'{Fore.RED}\u2718{Fore.RESET}'

    def iocs_file(self):
        return self.iocs / 'known_iocs.txt'

    def save_iocs_csv(self):
        if not self.results.exists():
            self.results.mkdir(parents=True)
        timestr = time.strftime("%Y%m%d-%H%M%S")
        return self.results / f'{WRK.hostname}_{timestr}.csv'

    def sha256(self, fname):
        hash_sha256 = hashlib.sha256()
        with open(fname, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()

    def read_file(self):
        with open(self.iocs_file(), 'r') as f:
            next(f)  # skip file header starting with '#'
            data = [data.strip() for data in f.readlines()]
        return data


def main(drivepath, ioc=None, infile=None):
    # Check if python version is v3.6+
    if sys.version_info[0] == 3 and sys.version_info[1] <= 5:
        sys.exit(f"\n{WRK.error} Please use python version 3.6 or higher.\n")

    WRK.count = 0
    if ioc:
        with open(WRK.save_iocs_csv(), 'w', newline='') as csvfile:
            fieldnames = ['Path', 'Size', 'Created', 'Hash']  # nopep8
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)  # nopep8
            writer.writeheader()
            for root, _, files in tqdm(os.walk(drivepath),
                                       ascii=True,
                                       desc=f"{WRK.processing} Searching for IOCs on {WRK.hostname}",
                                       ncols=80, unit=" files"):
                for filename in files:
                    for item in ioc:
                        if fnmatch.fnmatch(filename, item+r'*', flags=fnmatch.IGNORECASE):
                            try:
                                path = os.path.join(root, filename)
                                created = datetime.fromtimestamp(os.stat(path).st_ctime)  # nopep8
                                size = os.stat(path).st_size
                                writer.writerows([{'Path': path,
                                                   'Size': size,
                                                   'Created': f"{created:%Y-%m-%d}",
                                                   'Hash': WRK.sha256(path)}])
                                WRK.count += 1
                            except PermissionError:
                                continue
                            except WindowsError:
                                continue
                            except Exception as err:
                                print(f"{WRK.error} {err}")

    elif infile:
        # check if IOC's file is empty (no IOCs)
        if os.path.getsize(WRK.iocs_file()) < 40:
            sys.exit(f"\n{WRK.error} Missing IOCs -- The {WRK.iocs_file()} file appears to be empty.\n")  # nopep8

        ioc_str = WRK.read_file()
        with open(WRK.save_iocs_csv(), 'w', newline='') as csvfile:
            fieldnames = ['Path', 'Size', 'Created', 'Hash']  # nopep8
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)  # nopep8
            writer.writeheader()
            for root, _, files in tqdm(os.walk(drivepath),
                                       ascii=True,
                                       desc=f"{WRK.processing} Searching for IOCs on {WRK.hostname}",
                                       ncols=80, unit=" files"):
                for filename in files:
                    if filename.lower() in (name.lower() for name in ioc_str):
                        try:
                            path = os.path.join(root, filename)
                            created = datetime.fromtimestamp(os.stat(path).st_ctime)  # nopep8
                            size = os.stat(path).st_size
                            WRK.count += 1
                            writer.writerows([{'Path': path,
                                               'Size': size,
                                               'Created': f"{created:%Y-%m-%d}",
                                               'Hash': WRK.sha256(path)}])
                        except (PermissionError, WindowsError):
                            continue
                        except Exception as err:
                            print(f"{WRK.error} {err}")

    if WRK.count:
        print(f"\n{WRK.found} Found {WRK.count} IOCs on {WRK.hostname}")
        print(f"    --> Results saved to {WRK.save_iocs_csv()}")
    else:
        print(f"{WRK.notfound} No matches for IOCs")
        # Remove empty results - not the best method, but it works
        p = WRK.results.glob('**/*')
        files = [x for x in p if x.is_file()]
        for _file in files:
            if os.stat(_file).st_size < 25:
                os.remove(_file)


if __name__ == '__main__':
    banner = fr'''
          ________  ______   _______           __
         /  _/ __ \/ ____/  / ____(_)___  ____/ /__  _____
         / // / / / /      / /_  / / __ \/ __  / _ \/ ___/
       _/ // /_/ / /___   / __/ / / / / / /_/ /  __/ /
      /___/\____/\____/  /_/   /_/_/ /_/\__,_/\___/_/
      
                                    v{__version__}
                                    {__author__}
    '''

    print(f"{Fore.CYAN}{banner}{Fore.RESET}")

    WRK = Workers()
    parser = ArgumentParser()
    parser.add_argument('path', help="Path to search")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-i', '--ioc', nargs='+', type=str,
                       help="Single or list of IOCs (comma/space separated)")
    group.add_argument('-f', '--infile', action='store_true', default=WRK.iocs_file(),
                       help="Uses 'known_iocs.txt' file containing IOCs")

    args = parser.parse_args()

    if len(sys.argv[1:]) == 0:
        parser.print_help()
        parser.exit()

    main(args.path, args.ioc, args.infile)

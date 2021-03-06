import csv
import hashlib
import os
import socket
import sys
import time
from argparse import ArgumentParser
from datetime import datetime
from pathlib import Path, PurePath

import requests
from colorama import Fore
from colorama import init as color_init
import prettytable
from tqdm import tqdm

__author__ = "DFIRSec (@pulsecode)"
__version__ = "v0.0.8"
__description__ = "Quick and dirty method to search for filenames that match IOCs if hashes are not yet available."


class Workers(object):
    def __init__(self, count=None):
        self.count = count

    filepath = Path(__file__).parent
    results = filepath / 'results'
    iocs = filepath / 'iocs'
    hostname = socket.gethostname().upper()
    color_init()

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

    @staticmethod
    def sha256(fname):
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


def ptable_to_term():
    # output latest csv file to terminal
    csv_files = Path(WRK.results).glob('*.csv')
    latest_csv = max(csv_files, key=os.path.getctime)

    with open(latest_csv) as f:
        x = prettytable.from_csv(f, delimiter=',')
    x.align = 'l'
    print(x)


def remove_output():
    # Remove empty results - not the best method, but it works
    csv_files = Path(WRK.results).glob('*.csv')
    files = [x for x in csv_files if x.is_file()]
    for csv in files:
        if os.stat(csv).st_size < 25:
            os.remove(csv)


def main(drivepath, ioc=None, infile=None):
    # Check if python version is v3.6+
    if sys.version_info[0] == 3 and sys.version_info[1] <= 5:
        sys.exit(f"\n{WRK.error} Please use python version 3.6 or higher.\n")

    WRK.count = 0
    if ioc:
        # check if ioc contains spaces
        if [i for i in ioc[:-1] if ',' not in str(i.split(','))]:
            sys.exit(f'Surround IOC string that contains spaces with double quotes, e.g., {Fore.LIGHTMAGENTA_EX}"find me now.zip"{Fore.RESET}.')  # nopep8
        with open(WRK.save_iocs_csv(), 'w', newline='') as csvfile:
            fieldnames = ['Path', 'Size', 'Created', 'Hash']  # nopep8
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)  # nopep8
            writer.writeheader()
            try:
                for root, _, files in tqdm(os.walk(drivepath),
                                           ascii=True,
                                           desc=f"{WRK.processing} Searching for IOCs on {WRK.hostname}",
                                           ncols=80, unit=" files"):
                    for filename in files:
                        for item in ioc:
                            try:
                                if PurePath(filename).match(item.strip(',')+r'*'):
                                    path = os.path.join(root, filename)
                                    created = datetime.fromtimestamp(os.stat(path).st_ctime)  # nopep8
                                    size = os.stat(path).st_size
                                    writer.writerows([{'Path': path,
                                                       'Size': size,
                                                       'Created': f"{created:%Y-%m-%d}",
                                                       'Hash': WRK.sha256(path)}])
                                    WRK.count += 1
                            except (PermissionError, WindowsError):
                                continue
                            except Exception as err:
                                print(f"{WRK.error} {err}")
            except KeyboardInterrupt:
                csvfile.close()
                remove_output()
                sys.exit("\nAborted!")

    elif infile:
        # check if IOC's file is empty (no IOCs)
        if os.path.getsize(WRK.iocs_file()) < 40:
            sys.exit(f"\n{WRK.error} Missing IOCs -- The {WRK.iocs_file()} file appears to be empty.\n")  # nopep8

        ioc_str = WRK.read_file()
        with open(WRK.save_iocs_csv(), 'w', newline='') as csvfile:
            fieldnames = ['Path', 'Size', 'Created', 'Hash']  # nopep8
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)  # nopep8
            writer.writeheader()
            try:
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
            except KeyboardInterrupt:
                csvfile.close()
                remove_output()
                sys.exit("\nAborted!")

    if WRK.count:
        print(f"\n{WRK.found} Found {WRK.count} IOCs on {WRK.hostname}")
        print(f"    --> Results saved to {WRK.save_iocs_csv()}\n")
        ptable_to_term()
    else:
        print(f"{WRK.notfound} No matches for IOCs")
        remove_output()


if __name__ == '__main__':
    banner = fr'''
          ________  ______   _______           __
         /  _/ __ \/ ____/  / ____(_)___  ____/ /__  _____
         / // / / / /      / /_  / / __ \/ __  / _ \/ ___/
       _/ // /_/ / /___   / __/ / / / / / /_/ /  __/ /
      /___/\____/\____/  /_/   /_/_/ /_/\__,_/\___/_/
      
                                    {__version__}
                                    {__author__}
    '''

    print(f"{Fore.CYAN}{banner}{Fore.RESET}")

    WRK = Workers()
    parser = ArgumentParser()
    parser.add_argument('path', help="Path to search")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-i', nargs='+', type=str, metavar='',
                       help="Single or list of IOCs (comma separated)")
    group.add_argument('-f', action='store_true', default=WRK.iocs_file(),
                       help="Uses 'known_iocs.txt' file containing IOCs")

    args = parser.parse_args()

    # check if new version is available
    try:
        latest = requests.get("https://api.github.com/repos/dfirsec/ioc_finder/releases/latest").json()["tag_name"]  # nopep8
        if latest != __version__:
            print(f"{Fore.YELLOW}* Release {latest} of ioc_finder is available{Fore.RESET}")  # nopep8
    except Exception as err:
        print(f"{Fore.LIGHTRED_EX}[Error]{Fore.RESET} {err}\n")

    if len(sys.argv[1:]) == 0:
        parser.print_help()
    else:
        ioc = args.i
        infile = args.f
        main(args.path, ioc, infile)

import argparse
import logging
import os
import pwd
from jinja2 import Environment, FileSystemLoader
import codecs
import time
import sys

# Console colors
W = '\033[0m'  # white (normal)
R = '\033[31m' # red
G = '\033[32m' # green

def check_root():
    """
    Check if program is lauched with root privileges
    :return:
    """
    logging.info('Checking permissions...')
    if not os.geteuid() == 0:
        logging.warning('IoT-SecurityChecker must be run as root or with sudo privileges... Exiting')
        exit(1)
    logging.info(G+'Permissions OK'+W)


def back_to_user():
    os.setuid(pwd.getpwuid(os.getuid())[2])

def check_test_args(arg, key):
    """
    Check if a bruteforce can be launched or not
    :param args: list
    :param key: string
    :return: boolean
    """
    if arg == None:
        return False
    for i in arg[0].split(','):
        if i.upper() == key.upper() or i.upper() == 'ALL':
            return True
    return False


def check_args(args):
    """
    check if important arguments are set
    :param args:
    :return:
    """
    brute_choices=["SSH", "ALL", "TELNET", "FTP", "HTTP", "NONE"]
    if args.bruteforce is not None:
        for a in args.bruteforce[0].split(','):
            if a.upper() not in brute_choices:
                raise ValueError('Invalid Bruteforce choice: %s' % args.bruteforce)

    expl_choices=["DVR", "ROM0", "CISCOPVC", "DLINK", "HUMAX", "TVIP", "NONE", "ALL"]
    if args.exploits is not None:
        for a in args.exploits[0].split(','):
            if a.upper() not in expl_choices:
                raise ValueError('Invalid exploits choice: %s' % args.bruteforce)

    # Initialize logging subsystem
    numeric_loglevel = getattr(logging, args.loglevel.upper(), None)
    if not isinstance(numeric_loglevel, int):
        raise ValueError('Invalid log level: %s' % args.loglevel)
    logging.basicConfig(format='%(levelname)s: %(message)s',
                        level=numeric_loglevel)


def create_report(report_list, masscan_output_dir, masscan_file_prefix, template_name):
    timestr = time.strftime("%Y%m%d-%H%M%S")
    if len(report_list) != 0:
        try:
            # Setting template.
            env = Environment(loader=FileSystemLoader("templates"))
            template = env.get_template(template_name)
            html = template.render({'title': 'ProjectIOTSec Scan Report', 'report_list': report_list})
            # Write report.
            reportname=masscan_output_dir+masscan_file_prefix+timestr+".html"
            with open(reportname, "w") as f:
                f.write(template.render(
                    title='ProjectIOTSec Scan Report',
                    report_list=report_list
                ))
            # print(report_list)
            print(G+"Report : "+reportname+" successfully generated!"+W)

        except:
            e = sys.exc_info()[1]
            print("Error: %s" % e)
    else:
        # print the corresponding message depending on which template_name
        if template_name == "post_exploitation_scan_report_template.html":
            print("Report not generated as no new ports detected.")
        else:
            print("Report cannot be generated, no information found in report_list.")


def arg_parsing():
    """
    Handle the arguments
    :return: list
    """
    # Parse command-line arguments
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    # Masscan Arguments
    parser.add_argument("target",
                        help="Target list compatible with masscan range or a file with targets")
    parser.add_argument("-p", "--prefix", default="scan-",
                        help="Prefix for the masscan output files")
    parser.add_argument("-b", "--binary", default="masscan",
                        help="Masscan application path")
    parser.add_argument("-m", "--max-rate", type=int, default=100,
                        help="Masscan max rate in pps")
    parser.add_argument("-w", "--wait-time", type=int, default=30,
                        help="Masscan wait time")
    parser.add_argument("-d", "--out-dir", default="scan-results/",
                        help="Directory for the masscan output files")

    # Exploit Arguments
    parser.add_argument("-E", "--exploits", action='append', default=None,
                        help="Test some IoT exploits. Choose one or more from 'ALL', 'DVR', 'ROM0', 'CISCOPVC', 'DLINK', 'HUMAX', "
                             "'TVIP'. See the README file for more info")

    # BruteForcer Arguments
    parser.add_argument("-B", "--bruteforce", action='append', default=None,
                        help="Test some IoT Bruteforce. Choose one or more from 'ALL', 'SSH', 'FTP', 'HTTP', 'TELNET'. "
                             "See the README file for more info")
    parser.add_argument("-T", "--threads", type=int, default=3,
                        help="How many bruteforcing threads do you want?")

    # Logger Argument
    parser.add_argument("-v", "--loglevel", default="INFO", help="Set log level", choices=[
        "DEBUG",
        "WARNING",
        "INFO"])

    parser.add_argument("-o", "--report-output", default="IoT-SecurityChecker-report.csv",
                        help="Name of the report file in CSV format")

    args = parser.parse_args()
    check_args(args)
    return args


def print_banner():
    """
    just print banner title
    :return:
    """
    os.system('cat resources/logo')
    print('\n')

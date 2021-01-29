#!/usr/bin/python3

import sys
import os
import resources
import re
from bs4 import BeautifulSoup
from bruteforcers import FTP_BruteForcer, SSH_BruteForcer, Telnet_BruteForcer
from exploits.HomeController.VeraEdge_CVE_2019_13598 import VeraEdge_CVE_2019_13598
from exploits.HomeController.VeraEdge_CVE_2019_15498 import VeraEdge_CVE_2019_15498
from exploits.IP_Camera.Foscam_C2_CVE_2018_19070 import Foscam_C2_CVE_2018_19070
from exploits.IP_Camera.Foscam_C2_CVE_2018_19077 import Foscam_C2_CVE_2018_19077
from exploits.IP_Camera.DLink_Auth_RCE import DLink_Auth_RCE
from exploits.Router.ASUS_RT_AC3200_CVE_2018_14714 import ASUS_RT_AC3200_CVE_2018_14714
from exploits.NAS.QNAP_CVE_2019_7192 import QNAP_CVE_2019_7192
from scanner import Masscan_Scanner
from parsers import Masscan_Parser_Class
from databases import DataBase_Class
from Utils import *
import ast
from jinja2 import Environment, FileSystemLoader
import codecs
import time


def iot_guess(portlist, hostlist):
    """
    Try to guess if a device is an IoT or not, please review the iotDetectionKeyword.txt file
    :param portlist: list
    :param hostlist: list
    :return:
    """
    iot = []
    iot2 = []
    db = open('resources/iotDetectionKeyword.txt', 'r')
    # template:{'category':<cat-name>,'keywords':[list-of-key],'ports':[list-of-port],'manufacturers':[list-of-manufacturers],'vulns':[list-of-known-vulns]}

    dict_ip_category_matchcount = {}

    # for each category of IoT defined inside the iotDetection.txt file perform an IoT identification
    # TODO refactoring -> too much for loops!
    for cat in db.readlines():
        logging.debug('Cat: '+cat)
        my_dict = {}
        try:
            my_dict = ast.literal_eval(cat)
        except:
            logging.warning(R+'Error during the eval evaluation of the dict'+W)
            logging.debug(R + 'Log error line: ' + cat+W)

        # IoT detection based on open ports
        for device in portlist:
            logging.debug('DeviceA: ' + str(device))
            for port in device['ports']:
                logging.debug('Port: ' + port)
                if port in my_dict['ports']:
                    if device['ip'] not in dict_ip_category_matchcount:
                        dict_ip_category_matchcount[device['ip']] = {}
                    dict_ip_category_matchcount[device['ip']
                                                ][my_dict['category']] = 1
                    iot.append('Device: %s has Port %s open' %
                               (device['ip'], str(port)))
                    logging.debug(G+'Device: %s has Port %s open' %
                                  (device['ip'], str(port))+W)

        # IoT detection based on keywords and manufacturers in banner
        for device in hostlist:
            logging.debug('DeviceB: ' + str(device))
            for service in device['services']:
                logging.debug('Service: ' + service)
                for keyword in my_dict['keywords']:
                    logging.debug('Keyword: ' + keyword)
                    banner = service.split('projectiotsec')
                    if (keyword.upper() in str(banner[1:]) or keyword.lower() in str(banner[1:])
                            or keyword in str(banner[1:])) and keyword != '':
                        if device['ip'] not in dict_ip_category_matchcount:
                            dict_ip_category_matchcount[device['ip']] = {}
                        if my_dict['category'] in dict_ip_category_matchcount[device['ip']]:
                            dict_ip_category_matchcount[device['ip']
                                                        ][my_dict['category']] += 1
                        else:
                            dict_ip_category_matchcount[device['ip']
                                                        ][my_dict['category']] = 1
                        iot.append('Device: %s has keyword: %s in port %s banner: %s' %
                                   (device['ip'], str(keyword), service.split('projectiotsec')[0], str(banner[1:])))
                        logging.debug(G+'Device: %s has keyword: %s in port %s banner: %s' %
                                      (device['ip'], str(keyword), service.split('projectiotsec')[0], str(banner[1:]))+W)
                for manufacturer in my_dict['manufacturers']:
                    logging.debug('manufacturer: ' + manufacturer)
                    banner = service.split('projectiotsec')
                    if (manufacturer.upper() in str(banner[1:]) or manufacturer.lower() in str(banner[1:])
                            or manufacturer in str(banner[1:])) and manufacturer != '':
                        if device['ip'] not in dict_ip_category_matchcount:
                            dict_ip_category_matchcount[device['ip']] = {}
                        if my_dict['category'] in dict_ip_category_matchcount[device['ip']]:
                            dict_ip_category_matchcount[device['ip']
                                                        ][my_dict['category']] += 1
                        else:
                            dict_ip_category_matchcount[device['ip']
                                                        ][my_dict['category']] = 1
                        iot.append('Device: %s has manufacturer: %s in port %s banner: %s' %
                                   (device['ip'], str(manufacturer), service.split('projectiotsec')[0], str(banner[1:])))
                        logging.debug(G+'Device: %s has manufacturer: %s in port %s banner: %s' %
                                      (device['ip'], str(manufacturer), service.split('projectiotsec')[0], str(banner[1:]))+W)

    # determine most likely category based on number of matches
    for ip in dict_ip_category_matchcount:
        max_value = max(dict_ip_category_matchcount[ip].values())
        max_list = []
        for category in dict_ip_category_matchcount[ip]:
            if dict_ip_category_matchcount[ip].get(category) == max_value:
                max_list.append(category)

        for category in max_list:
            iot2.append('Device ' + ip +
                        ' is possibly compatible with ' + category + ' exploits')

    return iot, iot2

# set exploit status for the specific IP_Address


def set_exploit_status(exploit_ip, exploit_status):
    for device in report_list:
        if device['IP'][0] == exploit_ip:
            # set that device's exploit status
            device['Exploits'].append(exploit_status)

# set bruteforce status for the specific IP_Address


def set_bruteforce_status(exploit_ip, bruteforce_status):
    for device in report_list:
        if device['IP'][0] == exploit_ip:
            # set that device's exploit status
            device['Bruteforce'].append(bruteforce_status)


if __name__ == '__main__':
    # print startup screen
    os.system('cat resources/banner')
    check_root()

    # menu
    print("1. Scan Network")
    print("2. Post Exploitation Scan")
    print("3. Exit")
    choice = input("\nPlease choose option number: ")

    if (choice == '1'):

        masscan_file_prefix = input(
            "Enter the Prefix for the masscan output files (default = 'scan-') : ") or "scan-"
        masscan_binary_path = input(
            "Enter Masscan application path (default = 'masscan') : ") or "masscan"
        masscan_max_rate = input(
            "Masscan max rate in pps (default = 100) : ") or "100"
        masscan_wait_time = input(
            "Masscan wait time (default = 30) : ") or "30"
        masscan_output_dir = input(
            "Directory for the masscan output files (default = 'scan-results/') : ") or "scan-results/"
        if not os.path.exists(masscan_output_dir):
            os.makedirs(masscan_output_dir)
        ip_target_range = input("Enter IP range with CIDR : ")
        scanner = Masscan_Scanner.Masscan(target=ip_target_range,
                                          prefix=masscan_file_prefix,
                                          binary=masscan_binary_path,
                                          max_rate=masscan_max_rate,
                                          outdir=masscan_output_dir,
                                          wait_time=masscan_wait_time)

        ip_validity = scanner.check_ip_format(ip_target_range)
        while(ip_validity == False):
            ip_target_range = input("Enter IP range with CIDR : ")
            ip_validity = scanner.check_ip_format(ip_target_range)
        scanner.check_binary()
        scanner.check_system()
        scanner.run()
        scanner.cleanup()

        # parsing masscan output
        parser = Masscan_Parser_Class.Masscan_Parser(
            file=masscan_output_dir+scanner.get_outfile())
        parsed_list = parser.parse()
        logging.info('Inserting data into scan DB...')
        back_to_user()
        db = DataBase_Class.Database()
        tab_name = scanner.get_outfile().strip('.txt').replace('-', '_')
        db.create_scan_table(tab_name)
        db.insert_data(tab_name, parsed_list)
        rows = db.extract_dist_ip(tab_name)
        rows_2 = db.extract_first_ip(tab_name)
        rows_3 = db.extract_last_ip(tab_name)

        # db.print_db_results(rows)
        device_service_list, device_port_list = db.exctract_port_ip(
            tab_name, rows)
        db.close_db()

        iot_list, compatible_list = iot_guess(
            device_port_list, device_service_list)
        final_list = sorted(list(set(iot_list)))

        # Initialising list and dictionary for report generation
        report_list = []
        dict_keys = ["IP", "Port", "Banner", "Exploits", "Bruteforce"]
        report_dict = {key: [] for key in dict_keys}

        # Initialising variables
        last_ip = ''
        last_port = ''
        first_ip = ''

        # Obtain first ip in table
        for row in rows_2:
            first_ip = row[0]

        # Obtain last ip in the table
        for row in rows_3:
            last_ip = row[0]
            last_port = row[1]

        # Append the first IP
        report_dict["IP"].append(first_ip)

        counter = 1
        previous_ip = ''

        # Append to report_list through iterating the db
        for row in rows:
            # counter += 1
            ip = ''
            port = ''

            for key in row.keys():
                if key == 'IP':
                    ip = row[key]
                    if ip == first_ip:
                        pass

                    elif ip != previous_ip:
                        # Appends the dictionary to list
                        for line in compatible_list:
                            if (' ' + previous_ip + ' ') in line:
                                report_dict["Banner"].append(line)
                        report_dict_copy = report_dict.copy()
                        report_list.append(report_dict_copy)

                        # Reset dict key values
                        report_dict = {key: [] for key in dict_keys}
                        report_dict["IP"].append(ip)

                else:
                    port = row[key]
                    report_dict["Port"].append(port)

                    for text in final_list:
                        if (' ' + ip + ' ') in text:
                            if (' ' + port + ' ') in text:
                                report_dict["Banner"].append(text)

            if last_ip == ip and last_port == port:
                for line in compatible_list:
                    if (' ' + ip + ' ') in line:
                        report_dict["Banner"].append(line)
                report_dict_copy = report_dict.copy()
                report_list.append(report_dict_copy)

            previous_ip = row[0]

        # set template_name for network scan HTML report
        template_name = 'network_scan_report_template.html'
        try:
            # Loop for devices menu to allow user to continuously exploit multiple devices
            while True:
                print('\nList of all records found:\n')
                print('1. IP = ' + first_ip)

                counter = 1
                previous_ip = ''

                for row in rows:
                    # counter += 1
                    ip = ''
                    port = ''

                    for key in row.keys():
                        if key == 'IP':
                            ip = row[key]
                            if ip == first_ip:
                                pass

                            elif ip != previous_ip:
                                for line in compatible_list:
                                    if (' ' + previous_ip + ' ') in line:
                                        print('\033[32m   ' + line + '\033[0m')
                                counter += 1
                                print('\n%s. %s = %s' %
                                      (counter, key, row[key]))

                        else:
                            port = row[key]
                            print('   %s = %s' % (key, row[key]))

                            for text in final_list:
                                if (' ' + ip + ' ') in text:
                                    if (' ' + port + ' ') in text:
                                        print('   ' + text)

                    if last_ip == ip and last_port == port:
                        for line in compatible_list:
                            if (' ' + ip + ' ') in line:
                                print('\033[32m   ' + line + '\033[0m')

                    previous_ip = row[0]

                print('\nTotal result: '+str(counter))

                while True:
                    # ask for ip to exploit
                    exploit_ip = input(
                        "\nPlease enter the IP address to exploit: ")
                    regex = '^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
                    r = re.compile(regex)
                    if r.match(exploit_ip):
                        break
                    else:
                        print("Invalid IP address! ")

                print(exploit_ip + " may be compatible with the following exploits: \n")

                # try to get categories of exploits selected ip may be compatible with
                categories = []
                for line in compatible_list:
                    if (' ' + exploit_ip + ' ') in line:
                        x = re.search(
                            r"possibly compatible with ([\w_]+)", line)
                        if x:
                            if x.group(1) not in categories:
                                categories.append(x.group(1))

                # print out categories
                option_exploit_dict = {}
                counter = 1
                for category in categories:
                    print('   ' + category)
                    print('   '+'='*len(category))
                    filenames = os.listdir("exploits/"+category)
                    for filename in filenames:
                        if filename != "__init__.py" and filename != "__pycache__":
                            if filename != "dos.py":
                                option_exploit_dict[counter] = filename
                                print(str(counter) + '. ' + filename)
                                counter += 1
                    print()

                # option at which bruteforcers start
                option_bruteforce_start = counter

                # print out bruteforcers
                # HARDCODED PRINTING OUT OF BRUTEFORCERS (for now)
                print('   ' + 'Bruteforcers')
                print('   '+'='*len('Bruteforcers'))
                option_exploit_dict[counter] = 'FTP Bruteforcer'
                print(str(counter) + '. FTP Bruteforcer')
                counter += 1

                option_exploit_dict[counter] = 'SSH Bruteforcer'
                print(str(counter) + '. SSH Bruteforcer')
                counter += 1

                option_exploit_dict[counter] = 'Telnet Bruteforcer'
                print(str(counter) + '. Telnet Bruteforcer')
                counter += 1
                print()

                # ask for option of exploit
                while True:
                    option = input("Please enter choice of exploit: ")
                    if int(option) in range(1, counter):
                        break
                    else:
                        print("Invalid choice! Please try again.")

                if int(option) < option_bruteforce_start:
                    # run exploit
                    exploit_selected = option_exploit_dict.get(int(option))
                    exploit_selected = exploit_selected.replace(".py", "")
                    exploit_status = eval(exploit_selected)(exploit_ip)
                    # set exploit status in report_list
                    set_exploit_status(exploit_ip, exploit_status)
                else:
                    target_list = []
                    target_list.append(exploit_ip)
                    # bruteforce selected
                    if option_exploit_dict.get(int(option)) == 'FTP Bruteforcer':
                        # ftp bruteforce
                        target_port = input(
                            "Please enter the target port (default = 21) : ") or "21"
                        ftpBrute = FTP_BruteForcer.FTP_BruteForcer(target_list=target_list, target_port=target_port,
                                                                   credfile='resources/wordlists/mirai.txt',
                                                                   thread=3)
                        bruteforce_status_list = ftpBrute.run()
                    elif option_exploit_dict.get(int(option)) == 'SSH Bruteforcer':
                        # ssh bruteforce
                        target_port = input(
                            "Please enter the target port (default = 22) : ") or "22"
                        sshBrute = SSH_BruteForcer.SSH_BruteForcer(target_list=target_list, target_port=target_port,
                                                                   credfile='resources/wordlists/mirai.txt',
                                                                   thread=3)
                        bruteforce_status_list = sshBrute.run()
                    elif option_exploit_dict.get(int(option)) == 'Telnet Bruteforcer':
                        # telnet bruteforce
                        target_port = input(
                            "Please enter the target port (default = 23) : ") or "23"
                        telnetBrute = Telnet_BruteForcer.Telnet_BruteForcer(target_list=target_list, target_port=target_port,
                                                                            credfile='resources/wordlists/mirai.txt',
                                                                            thread=3)
                        bruteforce_status_list = telnetBrute.run()
                    # set bruteforce status in report_list
                    set_bruteforce_status(exploit_ip, bruteforce_status_list)
                    # for foundCredentials in bruteforce_status_list:
                    #     print(foundCredentials)

                global user_option

                while True:
                    user_option = input(
                        "Would you like to exploit another device? (y/n): ")

                    if (user_option == 'y'):
                        break

                    elif (user_option == 'n'):
                        break

                    else:
                        print("Please input a valid option")
                        continue

                if (user_option == 'n'):
                    # delete the "temporary" scan-result text file
                    textFilePath = masscan_output_dir + scanner.get_outfile()
                    os.remove(textFilePath)

                    # generate HTML report
                    create_report(report_list, masscan_output_dir,
                                  masscan_file_prefix, template_name)
                    print('\n' + 'Program exiting...')
                    sys.exit(0)

                else:
                    continue
        except KeyboardInterrupt:
            # delete the "temporary" scan-result text file
            textFilePath = masscan_output_dir + scanner.get_outfile()
            os.remove(textFilePath)

            # generate HTML report
            create_report(report_list, masscan_output_dir,
                          masscan_file_prefix, template_name)
            print('\n' + 'Program exiting...')
            sys.exit(0)

    elif (choice == '2'):
        run = True
        template_name = 'post_exploitation_scan_report_template.html'
        while run:
            try:
                # request user for the filepath for the baseline HTML report
                htmlFilePath = input(
                    "Enter the file path for the baseline HTML report: ")

                # retrieve the html file content
                with open(htmlFilePath, 'r') as file:
                    html = file.read()

                # Initialising list of dictionary for baseline_list
                baseline_list = []
                dict_keys = ["IP", "Port"]
                baseline_dict = {key: [] for key in dict_keys}

                # Parse the html content and retrieve the first table
                soup = BeautifulSoup(html, 'html.parser')
                table = soup.find_all('table')[0]

                #  Populate baseline_list
                for row in table.find_all('tr')[1:]:
                    cells = row.find_all('td')
                    baseline_dict["IP"].append(cells[1].get_text())
                    baseline_dict["Port"] = list(
                        cells[2].get_text().split(","))
                    baseline_dict_copy = baseline_dict.copy()
                    baseline_list.append(baseline_dict_copy)

                    # have to reset baseline_dict for the next device
                    baseline_dict = {key: [] for key in dict_keys}
                # print(baseline_list)

                # run masscan
                print("\nPlease enter the following to run masscan.")
                masscan_file_prefix = input(
                    "Enter the Prefix for the Post-Exploitation Report file (default = 'post-exploitation-scan-') : ") or "post-exploitation-scan-"
                masscan_binary_path = input(
                    "Enter Masscan application path (default = 'masscan') : ") or "masscan"
                masscan_max_rate = input(
                    "Masscan max rate in pps (default = 100) : ") or "100"
                masscan_wait_time = input(
                    "Masscan wait time (default = 30) : ") or "30"
                masscan_output_dir = input(
                    "Directory for the Post-Exploitation output files (default = 'post-exploitation-results/') : ") or "post-exploitation-results/"
                if not os.path.exists(masscan_output_dir):
                    os.makedirs(masscan_output_dir)
                ip_target_range = input("Enter IP range with CIDR : ")
                scanner = Masscan_Scanner.Masscan(target=ip_target_range,
                                                  prefix=masscan_file_prefix,
                                                  binary=masscan_binary_path,
                                                  max_rate=masscan_max_rate,
                                                  outdir=masscan_output_dir,
                                                  wait_time=masscan_wait_time)
                ip_validity = scanner.check_ip_format(ip_target_range)
                while(ip_validity == False):
                    ip_target_range = input("Enter IP range with CIDR : ")
                    ip_validity = scanner.check_ip_format(ip_target_range)
                scanner.check_binary()
                scanner.check_system()
                scanner.run()
                scanner.cleanup()

                # parsing masscan output
                parser = Masscan_Parser_Class.Masscan_Parser(
                    file=masscan_output_dir+scanner.get_outfile())
                parsed_list = parser.parse()
                logging.info('Inserting data into scan DB...')
                back_to_user()
                db = DataBase_Class.Database()
                tab_name = scanner.get_outfile().strip('.txt').replace('-', '_')
                db.create_scan_table(tab_name)
                db.insert_data(tab_name, parsed_list)
                rows = db.extract_dist_ip(tab_name)
                rows_2 = db.extract_first_ip(tab_name)
                rows_3 = db.extract_last_ip(tab_name)

                # store the result in a post_exploitation_list
                post_exploitation_list = []
                post_exploitation_dict = {key: [] for key in dict_keys}

                # Initialising variables
                last_ip = ''
                last_port = ''
                first_ip = ''

                # Obtain first ip in table
                for row in rows_2:
                    first_ip = row[0]

                # Obtain last ip in the table
                for row in rows_3:
                    last_ip = row[0]
                    last_port = row[1]

                # Append the first IP
                post_exploitation_dict["IP"].append(first_ip)

                counter = 1
                previous_ip = ''

                # Append to post_exploitation_list through iterating the db
                for row in rows:
                    ip = ''
                    port = ''

                    for key in row.keys():
                        if key == 'IP':
                            ip = row[key]
                            if ip == first_ip:
                                pass

                            elif ip != previous_ip:
                                # Appends the dictionary to list
                                post_exploitation_dict_copy = post_exploitation_dict.copy()
                                post_exploitation_list.append(
                                    post_exploitation_dict_copy)

                                # Reset dict key values
                                post_exploitation_dict = {
                                    key: [] for key in dict_keys}
                                post_exploitation_dict["IP"].append(ip)

                        else:
                            port = row[key]
                            post_exploitation_dict["Port"].append(port)

                    if last_ip == ip and last_port == port:
                        post_exploitation_dict_copy = post_exploitation_dict.copy()
                        post_exploitation_list.append(
                            post_exploitation_dict_copy)

                    previous_ip = row[0]
                # print(post_exploitation_list)

                # compare post_exploitation_list against baseline_list, & store the results in report_list (which will be used in report generation)
                report_list = []
                report_dict = {key: [] for key in dict_keys}
                for baseline_device in baseline_list:
                    for post_exploitation_device in post_exploitation_list:
                        if baseline_device['IP'][0] == post_exploitation_device['IP'][0]:
                            new_ports = list(set(post_exploitation_device['Port']).difference(
                                baseline_device['Port']))
                            if len(new_ports) != 0:
                                report_dict['IP'] = baseline_device['IP']
                                report_dict['Port'] = new_ports
                                report_dict_copy = report_dict.copy()
                                report_list.append(report_dict_copy)
                # print(report_list)

                run = False
            except OSError as e:
                print(e)
                run = True

        # delete the "temporary" scan-result text file
        textFilePath = masscan_output_dir + scanner.get_outfile()
        os.remove(textFilePath)

        # generate post exploitation HTML report
        create_report(report_list, masscan_output_dir,
                      masscan_file_prefix, template_name)
        print('\n' + 'Program exiting...')
        sys.exit(0)

    elif (choice == '3'):
        print("Exiting...")
        sys.exit(0)
    else:
        print("Invalid choice! Exiting...")
        sys.exit(0)

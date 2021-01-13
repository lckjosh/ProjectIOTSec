#!/usr/bin/python3

import sys
import os
import exploits
import resources
from scanner import Masscan_Scanner
from parsers import Masscan_Parser_Class
from databases import DataBase_Class
from Utils import *
import ast


def iot_guess(portlist, hostlist):
    """
    Try to guess if a device is an IoT or not, please review the iotDetectionKeyword.txt file
    :param portlist: list
    :param hostlist: list
    :return:
    """
    iot = []
    db = open('resources/iotDetectionKeyword.txt','r')
    ##template:{'category':<cat-name>,'keywords':[list-of-key],'ports':[list-of-port],'manufacturers':[list-of-manufacturers],'vulns':[list-of-known-vulns]}

    # for each category of IoT defined inside the iotDetection.txt file perform an IoT identification
    # TODO refactoring -> too much for loops!
    for cat in db.readlines():
        logging.debug('Cat: '+cat)
        my_dict = {}
        try:
            my_dict = ast.literal_eval(cat)
        except:
            logging.warning(R+'Error during the eval evaluation of the dict'+W)
            logging.debug(R +'Log error line: ' + cat+W)

        #IoT detection based on open ports
        for device in portlist:
            logging.debug('DeviceA: ' + str(device))
            for port in device['ports']:
                logging.debug('Port: ' + port)
                if port in my_dict['ports']:
                    iot.append('Device: %s has Port %s open, possibly compatible with %s exploits' %
                                 (device['ip'], str(port), my_dict['category']))
                    logging.debug(G+'Device: %s has Port %s open, possibly compatible with %s exploits' %
                                 (device['ip'], str(port), my_dict['category'])+W)

        # IoT detection based on keywords in banner
        for device in hostlist:
            logging.debug('DeviceB: ' + str(device))
            for service in device['services']:
                logging.debug('Service: ' + service)
                for keyword in my_dict['keywords']:
                    logging.debug('Keyword: ' + keyword)
                    banner = service.split('/')
                    if (keyword.upper() in str(banner[1:]) or keyword.lower() in str(banner[1:])
                        or keyword in str(banner[1:])) and keyword != '':
                        iot.append('Device: %s has keyword: %s in port %s banner: %s' %
                                     (device['ip'], str(keyword), service.split('/')[0], str(banner[1:])))
                        logging.debug(G+'Device: %s has keyword: %s in port %s banner: %s' %
                                     (device['ip'], str(keyword), service.split('/')[0], str(banner[1:]))+W)
    return iot

if __name__=='__main__':
    # print startup screen
    os.system('cat resources/banner')
    check_root()

    # menu
    print("1. Scan Network")
    print("2. Help")
    print("3. Exit")
    choice = input("\nPlease choose option number: ")

    if (choice == '1'):

        masscan_file_prefix = input("Enter the Prefix for the masscan output files (default = 'scan-') : ") or "scan-"
        masscan_binary_path = input("Enter Masscan application path (default = 'masscan') : ") or "masscan"
        masscan_max_rate = input("Masscan max rate in pps (default = 100) : ") or "100"
        masscan_wait_time = input("Masscan wait time (default = 30) : ") or "30"
        masscan_output_dir = input("Directory for the masscan output files (default = 'scan-results/') : ") or "scan-results/"
        if not os.path.exists(masscan_output_dir):
            os.makedirs(masscan_output_dir)
        ip_target_range = input("Enter IP range with CIDR : ")
        scanner = Masscan_Scanner.Masscan(target=ip_target_range,
                                        prefix=masscan_file_prefix,
                                        binary=masscan_binary_path,
                                        max_rate=masscan_wait_time,
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
        parser = Masscan_Parser_Class.Masscan_Parser(file=masscan_output_dir+scanner.get_outfile())
        parsed_list = parser.parse()
        logging.info('Inserting data into scan DB...')
        back_to_user()
        db = DataBase_Class.Database()
        tab_name = scanner.get_outfile().strip('.txt').replace('-','_')
        db.create_scan_table(tab_name)
        db.insert_data(tab_name, parsed_list)
        rows = db.extract_dist_ip(tab_name)
        rows_2 = db.extract_first_ip(tab_name)
        first_ip = ''
        for row in rows_2:
            first_ip = row[0]

        # db.print_db_results(rows)
        device_service_list, device_port_list = db.exctract_port_ip(tab_name, rows)
        db.close_db()

        iot_list = iot_guess(device_port_list, device_service_list)
        final_list = sorted(list(set(iot_list)))
        # for iot in sorted(list(set(iot_list))):
        #     print(iot)
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
                        counter+=1
                        print('\n%s. %s = %s' % (counter, key, row[key]))

                else:
                    port = row[key]
                    print('   %s = %s' % (key, row[key]))

                    for text in final_list:
                        if (ip + ' ') in text:
                            if port in text:
                                print('   ' + text)

                               

            previous_ip = row[0]           

        print('\nTotal result: '+str(counter))
        
        

        # print("network scan")
    elif (choice == '2'):
        print("help")
    elif (choice == '3'): 
        print("Exiting...")
        sys.exit(0)
    else: 
        print("Invalid choice! Exiting...")
        sys.exit(0)

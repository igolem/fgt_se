#! /usr/local/bin/python3

# file: fgt-ip-pool-assignment.py
# author: jason mueller
# created: 2021-01-30
# last modified: 2021-02-06

# purpose:
# determine the assigned NAT IP address from a set of overload NAT pools on a FortiGate
# for a given source IP address

# usage:
# use at your own risk
# there are no explicit or implied warranties or guarantees

# python version: 3.7.2

import sys


# is_ipv4_format
# verify supplied string is valid IPv4 address format
#   All IPv4 addresses from 0.0.0.0 through 255.255.255.255 are true
# returns: True or False
# created: 2019-01-05
# last modified: 2019-01-26
def is_ipv4_format(candidate):
    is_ipv4 = True            

    try:
        octets = list(map(int, candidate.split('.')))

        # verify IP address contains four components
        if len(octets) != 4:
            is_ipv4 = False

        # verify values are integer versions of binary octets in candidate IP
        else:
            for octet in octets:
                if (octet < 0 or octet > 255):
                    is_ipv4 = False
    except:
        is_ipv4 = False
        
    return is_ipv4


# valid_ipv4_unicast
# purpose: verify supplied string is a valid IPv4 unicast *destination* address
#   verifies address is not in some reserved ranges not common in production or testing
#   comment or uncomment preferred reserved address checks per your preference
# returns: True or False
# created: 2018-12-28
# last modified: 2019-01-27
def valid_ipv4_unicast(candidate):
    valid_unicast = True            

    try:
        octets = list(map(int, candidate.split('.')))
        # verify supplied string conforms to IPv4 format

        valid_unicast = is_ipv4_format(candidate)

        # octet value checks
        if valid_unicast:
            # verify first octet is not multicast or experimental (also catches broadcast)
            if (octets[0] > 223):
                valid_unicast = False

            # select reserved address checks follow
            # comment or uncomment as you see fit
            
            # verify not "host on this network"; only valid as source (RFC 1122)
            if octets[0] == 0:
                valid_unicast = False
            
            # verify not loopback (RFC 1122); sometimes used in testing
            if octets[0] == 127:
                valid_unicast = False
            
            # verify not self-assigned IP (RFC 3927)
            if (octets[0] == 169 and octets[1] == 254):
                valid_unicast = False

            # verify not reserved space for IETF protocol assignment (RFC 6890)
            if (octets[0] == 192 and octets[1] == 0 and octets[2] == 0):
                valid_unicast = False                
            
            # verify not automatic multicast tunneling (RFC 7450)
            if (octets[0] == 192 and octets[1] == 52 and octets[2] == 193):
                valid_unicast = False                
            
            # verify not AS 112 DNS redirection (RFC 7535)
            if (octets[0] == 192 and octets[1] == 31 and octets[2] == 196):
                valid_unicast = False                

            # verify not AS 112 DNS service (RFC 7534)
            if (octets[0] == 192 and octets[1] == 175 and octets[2] == 48):
                valid_unicast = False                
            
            # verify not 6to4 relay anycast (RFC 3068)
            if (octets[0] == 192 and octets[1] == 88 and octets[2] == 99):
                valid_unicast = False                
            
    except:
        valid_unicast = False

    return valid_unicast


# is_ipv4_range
# verify supplied start and end IPv4 addresses are a valid range of unicast IP addresses
#   note: there is no check if the range crosses reserved address space
# returns: True or False
# created: 2019-01-07
# last modified: 2019-01-27
def is_ipv4_range(start_ip, end_ip):
    valid_range = False
    
    try:
        start_valid = valid_ipv4_unicast(start_ip)
        end_valid = valid_ipv4_unicast(end_ip)
                
        if (start_valid and end_valid):
            start_octets = list(map(int, start_ip.split('.')))
            end_octets = list(map(int, end_ip.split('.')))

            # evalutate octet values as means to validate range
            if (end_octets == start_octets):
                valid_range = True

            elif (end_octets[0:3] == start_octets[0:3] and
                  end_octets[3] > start_octets[3]):
                valid_range = True

            elif (end_octets[0:2] == start_octets[0:2] and
                  end_octets[2] > start_octets[2]):
                valid_range = True

            elif (end_octets[0] == start_octets[0] and
                  end_octets[1] > start_octets[1]):
                valid_range = True

            elif (end_octets[0] > start_octets[0]):
                valid_range = True

    except:
        return False
    
    return valid_range


# ipv4_to_dec()
# convert a standard dotted quad IP address format
#     to its decimal number representation 
# returns: the decimal value for an IP or False
# created: 2021-01-30
# last modified: 2021-01-30
def ipv4_to_dec(quad_ip):
    try:
        if valid_ipv4_unicast(quad_ip):    
            octets = list(map(int, quad_ip.split('.')))
            ip_dec_value = octets[0]*2**24 + octets[1]*2**16 + octets[2]*2**8 + octets[3]
            return ip_dec_value
        else:
            return False
    except:
        return False


# dec_to_ipv4()
# convert a decimal value representation of an IP address
#     to its standard dotted quad decimal format
# returns: a standard formatted IP or False
# created: 2021-01-30
# last modified: 2021-01-30
def dec_to_ipv4(dec_ip_value):
    try:
        # determine assigned IP octet values by converting decimal representation to IP
        assign_octet = [None] * 4
        assign_octet[0] = dec_ip_value//2**24
        dec_ip_value -= assign_octet[0]*2**24
        assign_octet[1] = dec_ip_value//2**16
        dec_ip_value -= assign_octet[1]*2**16
        assign_octet[2] = dec_ip_value//2**8
        assign_octet[3] = dec_ip_value%2**8

        ip_quad = str(assign_octet[0]) + '.' +  str(assign_octet[1]) + '.' + \
                  str(assign_octet[2]) + '.' +  str(assign_octet[3])
    
        if is_ipv4_format(ip_quad):
            return ip_quad
        else:
            return False
    except:
        return False


# ipv4_pool_size()
# given two IP addresses, determine the number of IP addresses within the range between
# returns: the number of IPs in the range or False
# created: 2021-01-30
# last modified: 2021-01-30
def ipv4_pool_size(pool_start, pool_end):
    try:
        if (is_ipv4_range(pool_start, pool_end)):
            start_octets = list(map(int, pool_start.split('.')))
            end_octets = list(map(int, pool_end.split('.')))

            # calculate tne number of IP addresses in the IP pool
            range_size = 0
            range_size += (end_octets[0] - start_octets[0])*2**24
            range_size += (end_octets[1] - start_octets[1])*2**16
            range_size += (end_octets[2] - start_octets[2])*2**8
            range_size += (end_octets[3] - start_octets[3]) + 1
        
            return range_size
        else:
            return False
    except:
        return False


# calc_fgt_pool_assignment()
# cacluate a FortiGate SNAT IP address assignment given the source IP and IP pools
# ip_pools is assumed to be a list of valid IP ranges
#     x.x.x.x-y.y.y.y (i.e., 128.255.100.1-128.255.1.254)
# see FortiGate documentation for details on IP pool assignment algorithm
# returns: the NAT IP pool assignment or False
# created: 2021-01-30
# last modified: 2021-02-06
def calc_fgt_pool_assignment(src_ip, ip_pools):
    try:
        # determine individual IP pool sizes, total number of IPs in aggregate,
        # and list of tiers for determining pool assignment
        pool_sizes = []
        agg_pool_ips = 0
        pool_thresholds = []
        for pool in ip_pools:
            (pool_start, pool_end) = pool.split('-')
            pool_size = (ipv4_pool_size(pool_start, pool_end))
            pool_sizes.append(pool_size)
            agg_pool_ips += pool_size
            pool_thresholds.append(agg_pool_ips)

        # determine the IP pool assignment
        # where index calculated on aggregate pool IPs available to determine pool assignment
        src_dec_value = ipv4_to_dec(src_ip)
        initial_index = src_dec_value % agg_pool_ips
        pool_index = -1
        count = 0
        while pool_index < 0:
            if initial_index < pool_thresholds[count]:
                pool_index = count
            count += 1

        # find IP assignment within the assigned pool
        # where index is recalculated modulus based on individual pool size
        assigned_index = src_dec_value % pool_sizes[pool_index]
        (pool_start, pool_end) = ip_pools[pool_index].split('-')
        start_dec_value = ipv4_to_dec(pool_start)
        assigned_ip_dec = start_dec_value + assigned_index
        assigned_ip = dec_to_ipv4(assigned_ip_dec)

        if valid_ipv4_unicast(assigned_ip):
            return assigned_ip
        else:
            return False
    except:
        return False


def march_on_dunsinane():
    ip_pools = []

    # get source IP
    src_ip = input("Enter source IP: ")
    # verify the source IP is a valid IP address
    valid_ip = valid_ipv4_unicast(src_ip.strip())
    if not valid_ip:
        sys.exit("Invalid source ip: " + src_ip)

    # get number of IP pools used
    num_ranges = input("Number of assigned IP pools: ")
    try:
        num_ranges = int(num_ranges)
    except:
        sys.exit("Number of IP pools must be an integer")

    # get the IP range for each pool
    count = 0
    while num_ranges != 0:
        ip_pools.append(input("Enter IP pool range [" + str(count+1) + "]: "))

        # split pool into start and end IPs for validation
        try:
            (pool_start, pool_end) = ip_pools[count].split('-')
        except:
            sys.exit("IP range should be in the format 128.255.1.1-128.255.1.31")
        
        # validate the IP pool range is a valid range
        valid_range = is_ipv4_range(pool_start.strip(), pool_end.strip())
        if not valid_range:
            sys.exit("Invalid IP pool range: " + ip_pools[count])      

        count += 1
        num_ranges -= 1

    # calculate the NAT IP assignment for the provided IP source
    nat_ip = calc_fgt_pool_assignment(src_ip, ip_pools)
    
    print("\nNAT IP assignment:")
    print(nat_ip + "\n")

if __name__ == '__main__':
    march_on_dunsinane()


#----------------------------------------------------------------------------------
#
#   Author:     William Bourn
#   File:       MultiTrace.py
#   Version:    1.00
#
#   Description:
#   MultiTrace is a modification of Traceroute that determines all paths in the
#   presence of multiple path distributive routing algorithms such as ECMP
#      
#----------------------------------------------------------------------------------


#----------------------------------------------------------------------------------
#   Includes
#----------------------------------------------------------------------------------

from os import error
import socket
import ipaddress
import sys
from argparse import ArgumentParser


#----------------------------------------------------------------------------------
#   Command Line Argument Parser
#----------------------------------------------------------------------------------

parser = ArgumentParser(description="Multiple Route Traceroute")
parser.add_argument('--dst', '-D',
                    type = str,
                    help="Destination IP address or URL", 
                    required = True)

parser.add_argument('--maxttl', '-M',
                    type = int,
                    help="Maximum value for packet TTL", 
                    required = False,
                    default = 20)

parser.add_argument('--packets', '-P',
                    type = int,
                    help="Number of packets to send per unique TTL", 
                    required = False,
                    default = 100)

parser.add_argument('--timeout', '-T',
                    type = float,
                    help="Packet timeout in seconds", 
                    required = False,
                    default = 1.0)

parser.add_argument('--drop-limit', '-L',
                    type = int,
                    help="Number of dropped packets before failure", 
                    required = False,
                    default = 10)

#Export parameters
args = parser.parse_args()

#----------------------------------------------------------------------------------
#   Constants
#----------------------------------------------------------------------------------

#Define port and protocol numbers for ICMP
ICMP_PORT = 7
ICMP_PROTOCOL = socket.getprotobyname('ICMP')
UDP_PROTOCOL = socket.getprotobyname('UDP')

#----------------------------------------------------------------------------------
#   Classes
#----------------------------------------------------------------------------------

class HostUnreachableError(Exception):
    """
    Exception raised when a destination address is unreachable over a network

    @param dst:             The host that is unreachable
    @type dst:              str
    """

    def __init__(self, dst):
        self.dst = dst

class ExcessivePacketDropError(Exception):
    """
    Exception raised when too many packets are dropped during network communication

    @param dst:             The receiving host
    @type dst:              str
    """

    def __init__(self, dst):
        self.dst = dst


#----------------------------------------------------------------------------------
#   Functions
#----------------------------------------------------------------------------------

def Create_Layer_Topology(dst, maxTTL, packets, timeout, drop_limit):
    '''
    Generate a layer topology for multiple path routing to the destination address

    @param dst:             The destination IPv4 address of the protocol
    @type dst:              str

    @param maxTTL:          The maximum value the TTL may reach before the protocol
                            should declare the destination host unreachable
    @type maxTTL:           int

    @param packets:         The number of packets to send per unique TTL layer
    @type packets:          int

    @param timeout:         The ICMP receiving port timeout in seconds
    @type timeout:          float

    @param drop_limit:      The number of dropped packets before the protocol should
                            declare the destination host unreachable
    @type drop_limit:       int

    @return layer_topology: The network nodes organized into layers based upon the
                            number of hops from the source host
    @rtype layer_topology:  list(list(str))
    '''

    #Catch runtime errors
    try:
        
        #Initialize sending and receiving sockets
        send_socket = socket.socket(type = socket.SOCK_DGRAM, proto = UDP_PROTOCOL)
        recv_socket = socket.socket(type = socket.SOCK_RAW, proto = ICMP_PROTOCOL)

        #Bind receiving socket to the ICMP port
        recv_socket.bind(('',ICMP_PORT))

        #Create layer topology list
        layer_topology = []

        #Create Layer 0 dictionary
        hostname = socket.gethostname()
        hostaddr = socket.gethostbyname(hostname)
        L0_dict = {hostaddr : packets}
        layer_topology.append(L0_dict)

        #Iterate through TTL and create layer dictionaries
        TTL = 1
        drops = 0
        while TTL < maxTTL:
            
            #Create address dictionary for this layer
            address_dict = {}

            #Set TTL socket option for sending socket
            send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, TTL)
            
            #Send ICMP packets and listen for responses
            for i in range(packets):
                
                #Send an ICMP packet
                send_socket.sendto(('Hi').encode('utf-8'), (dst, ICMP_PORT))

                #Set receiving port timeout
                recv_socket.settimeout(timeout)

                #Wait for packets to be received or timeout
                while True:
                    try:
                        
                        #Receive ICMP packet
                        data, (address, add) = recv_socket.recvfrom(512)

                        #Increment dictionary for address
                        if address in address_dict:
                            address_dict[address] += 1
                        #Add address to dictionary if it doesn't already exist
                        else:
                            address_dict[address] = 1
                        break


                    #Executes when the receiving port times out
                    except socket.timeout:
                        #Increment drops and send next packet
                        drops += 1
                        break
                    
                    #Executes when packet retrieval fails
                    except socket.error:
                        #Keep trying to retrieve until timeout
                        continue
                
                #Raise an exception if the packet drop limit is exceeded
                if drops >= drop_limit:
                    raise ExcessivePacketDropError(dst)
            
            #Add address dictionary to layer topology list
            layer_topology.append(address_dict)

            #Stop iterating though TTL if the only member of the address dictionary is the destination address
            if ((dst in address_dict) & (len(address_dict) == 1)):
                break

            #Raise an exception if the address dictionary is empty
            if len(address_dict) == 0:
                raise HostUnreachableError(dst)

            #Increment the TTL value
            TTL += 1
        #Raise an exception if the maximum TTL value is exceeded
        if TTL >= maxTTL:
            raise HostUnreachableError(dst)

        #Close sockets
        recv_socket.close()
        send_socket.close()

        #Return the layer topology
        return layer_topology

    except error as error_type:

        #Close sockets
        recv_socket.close()
        send_socket.close()

        raise error_type   


def Create_Forwarding_Pair_Set(dst, maxTTL, packets, timeout, drop_limit):
    '''
    Generate a forwarding pair set for multiple path routing to the destination address 
    
    @param dst:             The destination IPv4 address of the protocol
    @type dst:              str

    @param maxTTL:          The maximum value the TTL may reach before the protocol
                            should declare the destination host unreachable
    @type maxTTL:           int

    @param packets:         The number of packets to send per unique TTL layer
    @type packets:          int

    @param timeout:         The ICMP receiving port timeout in seconds
    @type timeout:          float

    @param drop_limit:      The number of dropped packets before the protocol should
                            declare the destination host unreachable
    @type drop_limit:       int

    @return forwarding_set: The set of forwarding pairs for every layer transition in the routing protocol
                            between the source and destination host
    @rtype:                 list(list(str,str))
    
    '''
    
    #Catch runtime errors
    try:

        #Obtain the layer topology
        layer_topology = Create_Layer_Topology(dst, maxTTL, packets, timeout, drop_limit)

        #Create the forwarding set array
        forwarding_set = []

        #Iterate through the layers in descending order
        for transition in range(len(layer_topology) - 2,-1,-1):
            
            #Retrieve the high and low transition addresses
            low_transition_addr = list((layer_topology[transition]).keys())
            high_transition_addr = list((layer_topology[transition + 1]).keys())

            #Create the transition forwarding pairs list
            transition_forwarding = []

            #Check for single path forwarding
            if ((len(low_transition_addr) == 1) & (len(high_transition_addr) == 1)):
                #Create a forwarding pair from the address in each layer
                transition_forwarding.append([low_transition_addr[0],high_transition_addr[0]])
            
            #Check for merges
            elif len(high_transition_addr) == 1:
                #Iterate through addresses in low transition
                for addr in low_transition_addr:
                    #Ignore the destination address in the low transition
                    if addr == dst:
                        continue
                    #Create a forwarding pair for each address in the low transition to the address in the high transition
                    transition_forwarding.append([addr,high_transition_addr[0]])

            #Check for splits
            elif len(low_transition_addr) == 1:
                #Iterate through addresses in high transition
                for addr in high_transition_addr:
                    #Create a forwarding pair for each address in the high transition from the address in the low transition
                    transition.append([low_transition_addr[0],addr])
            
            #Transition is indeterminate
            else:
                #Iterate through addresses in the high transition
                for addr in high_transition_addr:
                    #Recursively call the function on the addresses in the high transition and obtain their forwarding sets
                    addr_forwarding_set = Create_Forwarding_Pair_Set(addr, maxTTL, packets, timeout)

                    #Retrieve the final layer transition from the forwarding set
                    recursed_transition_forwarding = addr_forwarding_set[transition]

                    #Add the recursed transition forwarding to the transition forwarding pair list
                    transition_forwarding.extend(recursed_transition_forwarding)
            
            #Add the transition forwarding pair list to the forwarding pair set
            forwarding_set.insert(0, transition_forwarding)

        #Return the forwarding set
        return forwarding_set

    except error as error_type:
        raise error_type


def Pathfind(src, dst, forwarding_set):
    '''
    Find the full set of paths described by the forwarding pair set between the source and destination hosts
    
    @param src:             The source IPv4 address of the protocol
    @type:                  str

    @param dst:             The destination IPv4 address of the protocol
    @type dst:              str

    @param forwarding_set:  The set of forwarding pairs for every layer transition in the routing protocol
                            between the source and destination host
    @type forwarding_set:   list(list(str,str))

    @return path_set:       The set off all paths used in the routing between the source and destination host
    @rtype path_set:        list(list(str))
    '''
    
    #Catch runtime errors
    try:

        #Create the path set
        path_set = []

        #Iterate through every forwarding pair of the first transition forwarding pair list
        for forwarding_pair in forwarding_set[0]:
            
            #Ignore forwarding pairs that do not have the source host as the low transition
            if forwarding_pair[0] == src:
                
                #Add forwarding pair to the path set if the destination host is the high transition
                if forwarding_pair[1] == dst:
                    path_set.append(forwarding_pair)
                
                #Recursively call the function using the high transitions as the source address and obtain their path sets
                else:
                    addr_path_set = Pathfind(forwarding_pair[1], dst, forwarding_set[1:len(forwarding_set)])
                    
                    #Add path source to front of all paths in recursed path set
                    for recursed_path in addr_path_set:
                        path = [src]
                        path.extend(recursed_path)

                        #Add path to path set
                        path_set.append(path)
        
        #Return the path set
        return path_set
    
    except error as error_type:
        raise error_type


def MultiTrace(dst_alias, maxTTL, packets, timeout, drop_limit):
    '''
    Perform a multi-path traceroute operation on the given destination address or URL

    @param dst_alias:       The destination IPv4 address or URL of the protocol
    @type dst_alias:        str

    @param maxTTL:          The maximum value the TTL may reach before the protocol
                            should declare the destination host unreachable
    @type maxTTL:           int

    @param packets:         The number of packets to send per unique TTL layer
    @type packets:          int

    @param timeout:         The ICMP receiving port timeout in seconds
    @type timeout:          float

    @param drop_limit:      The number of dropped packets before the protocol should
                            declare the destination host unreachable
    @type drop_limit:       int
    '''
    
    #Catch runtime errors
    try:

        #parse destination address alias as either an IPv4 address or as a URL
        try:
            dst = socket.gethostbyname(dst_alias)
        #Executes if alias cannot be parsed as IPv4 address or URL
        except socket.herror:
            raise ValueError

        #Create the forwarding par set
        forwarding_set =  Create_Forwarding_Pair_Set(dst, maxTTL, packets, timeout, drop_limit)
        
        #Determine the local IPv4 address
        hostname = socket.gethostname()
        hostaddr = socket.gethostbyname(hostname)

        #Create the path set
        path_set = Pathfind(hostaddr, dst, forwarding_set)

        #Print each path
        for path in path_set:
            print(path)
        
        #End function
        return
    
    except HostUnreachableError as err:
        print("Error: Host %s is unreachable." %err.dst)
        return
    
    except ExcessivePacketDropError as err:
        print("Error: Too many packets are dropped enroute to Host %s." %err.dst)
        return

    except error as error_type:
        raise error_type

#----------------------------------------------------------------------------------
#   Main Function Call
#----------------------------------------------------------------------------------

if __name__ == "__main__":
    
    MultiTrace(args.dst, args.maxttl, args.packets, args.timeout, args.drop_limit)


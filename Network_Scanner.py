#!/usr/bin/env python 

# Network_Scanner Python Tool Version 1.0
# Developed By Mostafa_Samy
# Github Link ==>> https://github.com/Mostafa-Samy-97

'''
Steps : 
1) Create ARP Resquest directed to broadcast Mac asking for IP 
2) Send Packets and receive response 
3) Parse the response 
4) Print the Result
'''

import scapy.all as scapy 


def scan(ip) :
    # use ARP to ask who has target IP
    arp_request = scapy.ARP(pdst=ip)

    # Send Destination Mac to Broadcast Mac
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')

    # Combine ARP_Request and Broadcast Mac together in one Variable 
    arp_request_broadcast = broadcast/arp_request

    # Send Packets and receive Only Answered Packets and Store them in a Variable
    answered_Packets_List = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    # Create a List of clients 
    clients_list = []    

    # loop inside the answered Packets list and print each element alone to analyse it
    for element in answered_Packets_List :
        # Create a dictionary for ip and mac 
        client_dict = {'ip' : element[1].psrc, 'mac' : element[1].hwsrc}
        # append client dictionary to the clients list
        clients_list.append(client_dict)
    return clients_list



def print_result(results_list) :
    
    print('\n[+] Scanning Network ...')
    # Print the Header of the Table of Results [ \t => Tab Space , \n => new line ]
    print("\nIP\t\t\tMAC Address\n----------------------------------------------")

    # loop in results_list we get from scan function and print the output    
    for client in results_list :
        # print Only the source ip and source mac address
        print(client["ip"] + '\t\t' + client['mac'] + '\n')



# Take IP Range Value from user 
ip = raw_input('Enter IP Range > ')
# execute scan function and store the output in variable
scan_result = scan(ip)
# execute the print_result function 
print_result(scan_result)

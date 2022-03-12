import time
import ipaddress
import random
import socket
import datetime


# Collect all ips from CIDR and the top 10 ports according to nmap
ip_list = [str(ip) for ip in ipaddress.IPv4Network('5.23.64.0/20')]
host_port_list = []
for ip in ip_list:
    # Avoid base network and broadcast address
    split_ip = ip.split(".")
    if split_ip[3] != "0" and split_ip[3] != "255":
        port_list = [80, 23, 443, 21, 22, 25, 3389, 110, 445, 139]
        host_port_list.append([ip, port_list])

randomized_list = []
# Compile a random list of ip and ports by
while len(host_port_list) > 0:
    # Get random index from collected ip and ports
    random_index = random.randint(0, len(host_port_list) - 1)
    # Get ip
    temp_ip = host_port_list[random_index][0]
    #temp_ip = socket.inet_aton(temp_ip)
    # Get 1 random port from our top 10
    random_port = random.randint(0, len(host_port_list[random_index][1]) - 1)
    temp_port = host_port_list[random_index][1][random_port]
    # Put together and append
    temp_ip_port = [temp_ip, temp_port]
    randomized_list.append(temp_ip_port)
    # delete the picked port from collection 
    del(host_port_list[random_index][1][random_port])
    # If there's no more ports then also delete the ip from collection
    if len(host_port_list[random_index][1]) == 0:
        del(host_port_list[random_index])

open_closed_list = []
# Go through randomized list and scan with 0.5 seconds delay
for host_port in randomized_list:
    time.sleep(0.5 + random.uniform(0, 0.2))
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        res = s.connect_ex((host_port[0], host_port[1]))  
        if res == 0:
            print("Ip: {} port: {} is open".format(host_port[0], host_port[1]))
            open_closed_list.append([host_port, datetime.datetime.now(), "Y"])
        elif res == 1:
            print("Insufficient packet buffers available to complete the operation")
        elif res == 2:
            print("The operation could not be completed within the time limit")
        elif res == 3:
            print("A connection is already established, so a new one cannot be established at this time")
        elif res == 4:
            print("The requested operation, protocol, or format is not supported")
        elif res == 5:
            print("The connection or connection attempt was aborted")
        elif res == 6:
            print("The requested operation would have to block in order to complete and the socket has been marked as nonblocking")
        elif res == 7:
            print("The attempted connection has been refused by the remote host")
        elif res == 8:
            print("The connection associated with this socket has been reset")
        elif res == 9:
            print("The requested operation cannot be completed because the socket is not in the connected state")
        elif res == 10:
            print("The requested operation cannot be performed because a similar operation is already in progress on this socket")
        elif res == 11:
            print("Ip: {} is in use but port: {} is not present".format(host_port[0], host_port[1]))
            open_closed_list.append([host_port, datetime.datetime.now(), "Y"])
        elif res == 12:
            print("The datagram is too large to be sent")
        elif res == 13:
            print("Cannot send using this socket because it has been shutdown for writing")
        elif res == 14:
            print("An address must be specified for t_connect() to connect to")
        elif res == 15:
            print("The operation could not be completed because the socket has been shutdown")
        elif res == 16:
            print("The option that you have requested or tried to set using t_setsockopt() or t_getsockopt() has not been recognized")
        elif res == 17:
            print("There is Out Of Band data waiting on the socket")
        elif res == 18:
            print("The socket sub-system could not allocate enough memory to complete the requested operation")
        elif res == 19:
            print("The requested address is not available")
        elif res == 20:
            print("The requested address is already in use")
        elif res == 21:
            print("The only address/protocol family supported is AF_INET")
        elif res == 22:
            print("The connect request failed because a previous connect was already in progress")
        elif res == 23:
            print("There was an error in the IP layer.")
        else:
            print("Ip: {} port: {} is not responding or closed".format(host_port[0], host_port[1]))
            open_closed_list.append([host_port, datetime.datetime.now(), "N"])
        s.close()
        
    except socket.gaierror:
        print("Ip: {} port: {} is not responding".format(socket.inet_ntoa(host_port[0]), host_port[1]))
        open_closed_list.append([host_port, datetime.datetime.now(), "N"])
        s.close()
    except socket.error:
        print("\ Server not responding !!!!")
        s.close()

with open("open_closed_list.csv", "w+") as writer:
    #host ip, port number scanned, timestamp, Y/N response
    writer.write("host ip,port number scanned,timestamp,Y/N response\n")
    for ip_port in open_closed_list:
        writer.write(ip_port[0][0] + "," + str(ip_port[0][1]) + "," + str(ip_port[1]) + "," + ip_port[2] + "\n")

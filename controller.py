import socket
import click
 #to store mac -> port mapping for learning switch behavior

mac_table = {}

#creating a tcp socket for the controller
controller_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

#bind controller to localhost on OpenFlow default port no 6633
controller_socket.bind(("127.0.0.1", 6633))

#listen for switch connections
controller_socket.listen(1)

click.secho("[*] Netweaver starting...", fg = "blue")
click.secho("[*] Waiting for switch to connect...", fg = 'blue')

#accept connection from open vswitch
conn, addr = controller_socket.accept()
click.secho(f"[+] Switch connected from : {addr}", fg = 'green')

while True:
    #Receive packet data from switch
    data = conn.recv(4096)

    #if no data is received, break the loop
    if not data:
        break

    #decode packet into redeable text
    packet_info = data.decode(errors = "ignore")

    click.secho("")
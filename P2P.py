import subprocess
import tkinter as tk
import threading
import queue
from time import sleep
import re

root = tk.Tk()
root.title('P2P Secure Chat')
root.resizable(False, False)
root.minsize(600,300)
process = None
message_q = queue.Queue()
host_pn = ""
connected = 1
disconnected = 0
status = disconnected

ip = subprocess.check_output("curl -s -4 https://ifconfig.me", shell=True, text=True).strip()

#validate entries for port number
def validate_pn_input(new_text):
    if new_text.isnumeric() and len(new_text) <= 5 or new_text == "":   #port numbers are numeric and have 5 characters max (0-65355)
        return True
    else:
        return False
vcmd_pn = (root.register(validate_pn_input), "%P")

#validate entries for ip
def validate_ip_input(new_text):        #ipv4 addresses can have max 15 characters 255 is max for an octet, and 3 .'s. 4 octets and 3 dots is 15
    if len(new_text) <= 15 or new_text == "":
        return True
    else:
        return False
vcmd_ip = (root.register(validate_ip_input), "%P")

#validate entries for send
def validate_send_input(new_text):
    if len(new_text) <= 100 or new_text == "":
        return True
    else:
        return False
vcmd_si = (root.register(validate_send_input), "%P")

#button functions
def connect(ip_local, pn_local):
    process.stdin.write(f"CONNECT:{ip_local} {pn_local}\n")
    process.stdin.flush()

def disconnect():
    process.stdin.write("DISCONNECT\n")
    process.stdin.flush()

def quit():
    process.stdin.write("QUIT\n")
    process.stdin.flush()
    root.quit()

#0th row for sending message bar
send_entry = tk.Entry(root, width=80, validate="key", validatecommand=vcmd_si)
send_entry.grid(row=0, column=0, columnspan=5)

#1st row for entry box
console_text = tk.Text(root, height=10, width=50, wrap="word")
console_text.grid(row=1, column=0, columnspan=6)
console_text.config(state=tk.DISABLED)
def write_to_console(message, color):
    console_text.config(state=tk.NORMAL)
    if color:
        console_text.insert(tk.END, message, color + "_tag")
        console_text.tag_config(color + "_tag", foreground=color)
    else:
        console_text.insert(tk.END, message)
    console_text.see(tk.END)
    console_text.config(state=tk.DISABLED)


scrollbar = tk.Scrollbar(root, command=console_text.yview)
scrollbar.grid(row=1, column=5, sticky="ns")
console_text.config(yscrollcommand=scrollbar.set)
root.grid_rowconfigure(0, weight=1)
root.grid_columnconfigure(0, weight=1)

#2nd row which is for hosting for a peer
host_ip_label = tk.Label(root, text= f"Your IP Address:")
host_ip_label.grid(row=2, column=0)

host_ip_text = tk.Label(root, text=f"{ip}")
host_ip_text.grid(row=2, column=1)

host_pn_label = tk.Label(root, text= f"Your Port Number:")
host_pn_label.grid(row=2, column=2)

#3rd row which is for connecting to a peer
peer_ip_label = tk.Label(root, text= f"Peer IP Address:")
peer_ip_label.grid(row=3, column=0)

peer_ip_entry = tk.Entry(root, validate="key", validatecommand=vcmd_ip)
peer_ip_entry.grid(row=3, column=1)

peer_pn_label = tk.Label(root, text= f"Peer Port Number:")
peer_pn_label.grid(row=3, column=2)

peer_pn_entry = tk.Entry(root, validate="key", validatecommand=vcmd_pn)
peer_pn_entry.grid(row=3, column=3)

connect_button = tk.Button(root, text="Connect")
connect_button.config(command=lambda: connect(peer_ip_entry.get(), peer_pn_entry.get()))
connect_button.grid(row=3, column=4)

disconnect_button = tk.Button(root, text="Disconnect")
disconnect_button.config(command=disconnect)
disconnect_button.grid(row=3, column=5)

#4th row for quitting
quit_button = tk.Button(root, text="Quit")
quit_button.config(command=quit)
quit_button.grid(row=4, column=4)

#for send button as it interacts with send entry and console text
def send(message):
    send_entry.delete(0, tk.END)
    send_entry.insert(0, "")
    console_text.config(state=tk.NORMAL)
    console_text.insert(tk.END, "You: " + message + "\n", "blue_tag")
    console_text.tag_config("blue_tag", foreground="blue")
    console_text.see(tk.END)
    console_text.config(state=tk.DISABLED)
    process.stdin.write(message + "\n")
    process.stdin.flush()

#functions to handle output from backend
def reader(q, fcn):
    for line in iter(fcn, ''):
        q.put(line)
    q.put("Backend exited\n")
    sleep(5)
    root.quit()

def connection(peer_ip, peer_port):
    if status == disconnected:
        peer_ip_entry.delete(0, tk.END)
        peer_ip_entry.insert(tk.END, peer_ip)
        peer_ip_entry.config(state=tk.DISABLED)

        peer_pn_entry.delete(0, tk.END)
        peer_pn_entry.insert(tk.END, peer_port)
        peer_pn_entry.config(state=tk.DISABLED)
        connect_button.config(state=tk.DISABLED)

def disconnection():
    if status == connected:
        peer_ip_entry.config(state=tk.NORMAL)
        peer_pn_entry.config(state=tk.NORMAL)
        connect_button.config(state=tk.NORMAL)

def pump_queue():
    global status
    try:
        while True:
            line = message_q.get_nowait()
            disconnect_pattern = "Peer has disconnected.\n"
            connect_pattern_client = r"Success in connecting to peer with IP address: ([\d\.]+)\. Port number: (\d+)\n"
            connect_pattern_server = r"Success in connecting to peer with IP address: ([\d\.]+)\.\n"
            peer_pattern = r"^PEER:\s*(.*)$\n"
            match = re.search(connect_pattern_client, line)
            match2 = re.search(connect_pattern_server, line)
            match3 = re.search(peer_pattern, line)
            if line == disconnect_pattern:
                disconnection()
                if status == connected:
                    write_to_console(line, "green")
                status = disconnected
            elif match:
                peer_ip = match.group(1)
                peer_port = match.group(2)
                connection(peer_ip, peer_port)
                status = connected
            elif match2:
                peer_ip = match2.group(1)
                connection(peer_ip, "N/A")
                status = connected
            elif match3:
                write_to_console(line, "red")
            else:
                write_to_console(line, "")
    except queue.Empty:
        pass
    root.after(50, pump_queue)

def run_backend():
    global process, host_pn
    process = subprocess.Popen(
        ["stdbuf", "-oL", "-i0","./main"],  # line-buffered stdout
        stdout=subprocess.PIPE,
        stdin=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    host_pn =  process.stdout.readline().strip()
    if not host_pn.isnumeric():
        message_q.put(host_pn)
        host_pn = "ERROR"
    threading.Thread(target=reader, args=(message_q, process.stdout.readline), daemon=True).start()
    threading.Thread(target=reader, args=(message_q, process.stderr.readline), daemon=True).start()
    pump_queue()

#send button is here since it needs to call functions which interacts with entries and text boxes
send_button = tk.Button(root, text="Send")
send_button.config(command=lambda: send(send_entry.get()))
send_button.grid(row=0, column=5)

#loop
run_backend()
host_pn_text = tk.Label(root, text=host_pn)
host_pn_text.grid(row=2, column=3)
root.mainloop()
import subprocess
import os
import tkinter as tk
#todo make a function to host backend
ip = subprocess.check_output("curl -s -4 https://ifconfig.me", shell=True, text=True).strip()

root = tk.Tk()
root.title('P2P Secure Chat')
root.resizable(False, False)
root.minsize(600,300)

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

#0th row for entry box
text_widget = tk.Text(root, wrap="word", width=50, height=10)           #todo make functionality for text box
text_widget.insert("1.0", "m\nm\nm\nm\nm\nm\nm\nm\nm\nm\nm\nm\nm\nx\nx\nx\nx\nx\nx\nx\nx\nx\nx\nx\nx\nx\n.")

text_widget.config(state=tk.DISABLED)
text_widget.grid(row=0, column=0, columnspan=6)

scrollbar = tk.Scrollbar(root, command=text_widget.yview)
scrollbar.grid(row=0, column=5, sticky="ns")

text_widget.config(yscrollcommand=scrollbar.set)

root.grid_rowconfigure(0, weight=1)
root.grid_columnconfigure(0, weight=1)

#first row which is for hosting for a peer
host_ip_label = tk.Label(root, text= f"Your IP Address:")
host_ip_label.grid(row=1, column=0)

host_ip_text = tk.Label(root, text=f"{ip}")
host_ip_text.grid(row=1, column=1)

host_pn_label = tk.Label(root, text= f"Your Port Number:")
host_pn_label.grid(row=1, column=2)

host_pn_entry = tk.Entry(root, validate="key", validatecommand=vcmd_pn)
host_pn_entry.grid(row=1, column=3)

host_button = tk.Button(root, text="Host")      #todo make host button work
host_button.grid(row=1, column=4)

#second row which is for connecting to a peer
peer_ip_label = tk.Label(root, text= f"Peer IP Address:")
peer_ip_label.grid(row=2, column=0)

peer_ip_entry = tk.Entry(root, validate="key", validatecommand=vcmd_ip)
peer_ip_entry.grid(row=2, column=1)

peer_pn_label = tk.Label(root, text= f"Peer Port Number:")
peer_pn_label.grid(row=2, column=2)

peer_pn_entry = tk.Entry(root, validate="key", validatecommand=vcmd_pn)
peer_pn_entry.grid(row=2, column=3)

connect_button = tk.Button(root, text="Connect")            #todo make connect button work
connect_button.grid(row=2, column=4)

disconnect_button = tk.Button(root, text="Disconnect")          #todo make disconnect button work
disconnect_button.grid(row=2, column=5)

#row 3 for quitting
quit_button = tk.Button(root, text="Quit")
quit_button.config(command=root.quit)       #todo fix this because i also want to quit backend
quit_button.grid(row=3, column=4)

#loop
root.mainloop()
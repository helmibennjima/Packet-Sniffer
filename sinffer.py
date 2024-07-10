from tkinter import *
from tkinter import ttk
from scapy.all import sniff, conf
from scapy.layers.inet import IP, TCP, UDP
from PIL import Image, ImageTk  # Import Pillow

def packet_callback(packet):
    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        result_text.insert(END, f"Source IP: {ip_layer.src}\n")
        result_text.insert(END, f"Destination IP: {ip_layer.dst}\n")
        
        if packet.haslayer(TCP):
            tcp_layer = packet.getlayer(TCP)
            result_text.insert(END, f"Source Port: {tcp_layer.sport}\n")
            result_text.insert(END, f"Destination Port: {tcp_layer.dport}\n")
        
        elif packet.haslayer(UDP):
            udp_layer = packet.getlayer(UDP)
            result_text.insert(END, f"Source Port: {udp_layer.sport}\n")
            result_text.insert(END, f"Destination Port: {udp_layer.dport}\n")

def start_sniffing(count):
    result_text.delete(1.0, END)  # Clear previous results
    result_text.insert(END, "Starting network sniffer...\n")
    sniff(prn=packet_callback, count=count)

def start_sniffing_with_interface(count, iface):
    result_text.delete(1.0, END)  # Clear previous results
    result_text.insert(END, f"Starting network sniffer on interface '{iface}'...\n")
    sniff(iface=iface, prn=packet_callback, count=count)

def start_sniffing_with_filter(count, filter_str):
    result_text.delete(1.0, END)  # Clear previous results
    result_text.insert(END, f"Starting network sniffer with filter '{filter_str}'...\n")
    sniff(filter=filter_str, prn=packet_callback, count=count)

def start_sniffing_with_options():
    count = int(count_entry.get())
    iface = iface_entry.get()
    filter_str = filter_entry.get()

    if iface and filter_str:
        start_sniffing_with_interface(count, iface)
        start_sniffing_with_filter(count, filter_str)
    elif iface:
        start_sniffing_with_interface(count, iface)
    elif filter_str:
        start_sniffing_with_filter(count, filter_str)
    else:
        start_sniffing(count)

root = Tk()
root.title("Packet Sniffer")
from datetime import datetime  # Import datetime module for timestamp

def packet_callback(packet):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]  # Get current timestamp
    result_text.insert(END, f"Timestamp: {timestamp}\n")
    
    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        result_text.insert(END, f"Source IP: {ip_layer.src}\n")
        result_text.insert(END, f"Destination IP: {ip_layer.dst}\n")
        
        if packet.haslayer(TCP):
            tcp_layer = packet.getlayer(TCP)
            result_text.insert(END, f"Source Port: {tcp_layer.sport}\n")
            result_text.insert(END, f"Destination Port: {tcp_layer.dport}\n")
        
        elif packet.haslayer(UDP):
            udp_layer = packet.getlayer(UDP)
            result_text.insert(END, f"Source Port: {udp_layer.sport}\n")
            result_text.insert(END, f"Destination Port: {udp_layer.dport}\n")
    
    result_text.insert(END, "\n")  # Add a blank line for separation


# Load and display logo image using Pillow
image = Image.open("logo.png")
photo = ImageTk.PhotoImage(image)
Label(root, image=photo).grid(row=0, column=0, columnspan=2, pady=10)

# Adding a title label
title_label = Label(root, text="Network Packet Sniffer", font=("Helvetica", 16, "bold"))
title_label.grid(row=1, column=0, columnspan=2, pady=10)

# Create a frame for the options
options_frame = Frame(root)
options_frame.grid(row=2, column=0, columnspan=2, pady=10, padx=10, sticky="ew")

# Create labels and entries for options
Label(options_frame, text="Packet Count:", font=("Helvetica", 12)).grid(row=0, column=0, padx=10, pady=5, sticky="w")
count_entry = Entry(options_frame)
count_entry.grid(row=0, column=1, padx=10, pady=5)
count_entry.insert(END, "10")  # Default count

Label(options_frame, text="Interface Name:", font=("Helvetica", 12)).grid(row=1, column=0, padx=10, pady=5, sticky="w")
iface_entry = Entry(options_frame)
iface_entry.grid(row=1, column=1, padx=10, pady=5)
iface_entry.insert(END, conf.iface)  # Default interface

Label(options_frame, text="BPF Filter (optional):", font=("Helvetica", 12)).grid(row=2, column=0, padx=10, pady=5, sticky="w")
filter_entry = Entry(options_frame)
filter_entry.grid(row=2, column=1, padx=10, pady=5)
filter_entry.insert(END, "")  # Default filter

# Create a frame for the results
results_frame = Frame(root)
results_frame.grid(row=3, column=0, columnspan=2, pady=10, padx=10, sticky="nsew")

# Add a scrollbar to the text widget
scrollbar = Scrollbar(results_frame)
scrollbar.pack(side=RIGHT, fill=Y)

# Create a text widget to display results
result_text = Text(results_frame, wrap=WORD, height=20, width=80, yscrollcommand=scrollbar.set, font=("Helvetica", 10))
result_text.pack(expand=True, fill=BOTH)
scrollbar.config(command=result_text.yview)

# Create a button to start sniffing with options
start_button = Button(root, text="Start Sniffing", command=start_sniffing_with_options, font=("Helvetica", 12, "bold"), bg="green", fg="white")
start_button.grid(row=4, column=0, columnspan=2, padx=10, pady=10)

# Configure grid to expand properly
root.grid_rowconfigure(3, weight=1)
root.grid_columnconfigure(1, weight=1)

# Start the main Tkinter event loop
root.mainloop()


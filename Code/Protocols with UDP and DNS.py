import pyshark
import numpy as np
import matplotlib.pyplot as plt
import tkinter as tk
import matplotlib
from varname import nameof
import subprocess
capts = []
cap0 = pyshark.FileCapture(
    r"C:\\Users\\Valentin\\Documents\\Etudes\\Q6.3\\Reseaux Informatiques\\TraceProjet\\EtV wVtwV appel simple 1.pcapng")
cap1 = pyshark.FileCapture(
    r"C:\\Users\\Valentin\\Documents\\Etudes\\Q6.3\\Reseaux Informatiques\\TraceProjet\\EtV wVtwV appel video 1.pcapng")
cap2 = pyshark.FileCapture(
    r"C:\\Users\\Valentin\\Documents\\Etudes\\Q6.3\\Reseaux Informatiques\\TraceProjet\\EtV 4GEt4GV appel simple 1.pcapng")
cap3 = pyshark.FileCapture(
    r"C:\\Users\\Valentin\\Documents\\Etudes\\Q6.3\\Reseaux Informatiques\\TraceProjet\\EtV 4GEt4GV appel video 1.pcapng")
capts.append(cap0)
capts.append(cap1)
capts.append(cap2)
capts.append(cap3)
dicDNS = {}
dicUDP = {}
for i in range(len(capts)):
    cap = capts[i]
    print("cap" + str(i) + ":")
    for pkt in cap:
        if "DNS" in pkt:
            for layer in pkt.layers:
                dicDNS[layer.layer_name] = dicDNS.get(layer.layer_name, 0) + 1
        if "UDP" in pkt :
            for layer in pkt.layers:
                dicUDP[layer.layer_name] = dicUDP.get(layer.layer_name, 0) + 1
print(dicDNS)
print(dicUDP)
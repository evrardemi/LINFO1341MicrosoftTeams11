import pyshark
import numpy as np
import matplotlib.pyplot as plt
import tkinter as tk
import matplotlib
from varname import nameof

matplotlib.use('TkAgg')
NbrCap = 4
#val : r"C:\\Users\\Valentin\\Documents\\Etudes\\Q6.3\\Reseaux Informatiques\\TraceProjet\\EtV wVtw appel simple 1.pcapng"
capts = []
cap0 = pyshark.FileCapture(r"C:\\Users\\Valentin\\Documents\\Etudes\\Q6.3\\Reseaux Informatiques\\TraceProjet\\EtV wVtwV appel simple 1.pcapng")
cap1 = pyshark.FileCapture(r"C:\\Users\\Valentin\\Documents\\Etudes\\Q6.3\\Reseaux Informatiques\\TraceProjet\\EtV wVtwV appel video 1.pcapng")
cap2 = pyshark.FileCapture(r"C:\\Users\\Valentin\\Documents\\Etudes\\Q6.3\\Reseaux Informatiques\\TraceProjet\\EtV 4GEt4GV appel simple 1.pcapng")
cap3 = pyshark.FileCapture(r"C:\\Users\\Valentin\\Documents\\Etudes\\Q6.3\\Reseaux Informatiques\\TraceProjet\\EtV 4GEt4GV appel video 1.pcapng")
capts.append(cap0)
capts.append(cap1)
capts.append(cap2)
capts.append(cap3)
dicIPWifi = {}
dicIP4G = {}

countIPWifi = 0
countIP4G = 0

for i in range(len(capts)):
    print("cap" + str(i) + ":")

    cap = capts[i]
    for pkt in cap:
        if "IP" in pkt:

                if i < 2:
                    if pkt.ip.src == "192.168.1.35":
                        dicIPWifi[pkt.ip.dst] = dicIPWifi.get(pkt.ip.dst, 0) + 1
                        countIPWifi += 1
                else:
                    if pkt.ip.src == "192.168.43.248":
                        dicIP4G[pkt.ip.dst] = dicIP4G.get(pkt.ip.dst, 0) + 1
                        countIP4G += 1
        if "IPV6" in pkt:
            if pkt.ipv6.src == "192.168.1.35":
                if i < 2:
                    dicIPWifi[pkt.ipv6.dst] = dicIPWifi.get(pkt.ipv6.dst, 0) + 1
                    countIPWifi += 1
                else:
                    dicIP4G[pkt.ipv6.dst] = dicIP4G.get(pkt.ipv6.dst, 0) + 1
                    countIP4G += 1
for a in dicIPWifi:
    dicIPWifi[a] = (100 * dicIPWifi[a]) / countIPWifi
for a in dicIP4G:
    dicIP4G[a] = (100 * dicIP4G[a]) / countIP4G


dicIPWifi = dict(sorted(dicIPWifi.items(), key=lambda item: -item[1]))
dicIP4G = dict(sorted(dicIP4G.items(), key=lambda item: -item[1]))

toPop = []
sumProp = 0.0
for item in dicIPWifi:
    if dicIPWifi[item] < 0.5:
        sumProp += dicIPWifi[item]
        toPop.append(item)
if sumProp != 0.0:
    dicIPWifi["Other<0.5%"] = sumProp
    for a in toPop:
        print(a)
        dicIPWifi.pop(a)
##################
toPop = []
sumProp = 0.0
for item in dicIP4G:
    if dicIP4G[item] < 0.5:
        sumProp += dicIP4G[item]
        toPop.append(item)
if sumProp != 0.0:
    dicIP4G["Other<0.5%"] = sumProp
    for a in toPop:
        #print(a)
        dicIP4G.pop(a)

labelsIPWifi = dicIPWifi.keys()
labelsIP4G = dicIP4G.keys()

sizesIPWifi = dicIPWifi.values()
sizesIP4G = dicIP4G.values()

fig1, axs1 = plt.subplots()
fig2, axs2 = plt.subplots()

axs1.pie(sizesIPWifi, labels=labelsIPWifi, autopct='%1.1f%%', pctdistance=0.8, labeldistance=1.05, radius=1.3, textprops={'size': 'smaller'})
axs1.set_title("Proportion des adresses de destination en utilisant le même Wi-Fi ", pad=20)#

axs2.pie(sizesIP4G, labels=labelsIP4G, autopct='%1.1f%%', pctdistance=0.8, labeldistance=1.05, radius=1.3, textprops={'size': 'smaller'})
axs2.set_title("Proportion des adresses de destination en utilisant 2 réseaux différents", pad=20)#

#fig1.suptitle("Proportion ip dest addresses using Wifi", fontsize=16)
#fig2.suptitle("Proportion ip dest addresses using 4G", fontsize=16)

fig1.savefig("Proportion ip dest addresses using Wifi" + ".svg", format="svg")
fig2.savefig("Proportion ip dest addresses using 4G" + ".svg", format="svg")

#plt.savefig("Proportion ip addresses and ports in cap" + ".svg", format="svg")
plt.show()


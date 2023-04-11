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
cap0 = pyshark.FileCapture(r"C:\\Users\\Valentin\\Documents\\Etudes\\Q6.3\\Reseaux Informatiques\\TraceProjet\\Appel telechargement.pcapng")
cap1 = pyshark.FileCapture(r"C:\\Users\\Valentin\\Documents\\Etudes\\Q6.3\\Reseaux Informatiques\\TraceProjet\\Appel avec son.pcapng")

capts.append(cap1)
capts.append(cap0)

dicSon = {}
countSon = 0
countSonNone = 0

dicSans = {}
countSans = 0
countSansNone = 0

for i in range(len(capts)):
    print("cap"+str(i)+":")

    cap = capts[i]
    countTcp=0
    for pkt in cap:
        if "TCP" in pkt:
            countTcp+=1
        if pkt.transport_layer != None:
            if i % 2 == 0:
                countSon += 1
                dicSon[pkt.transport_layer] = dicSon.get(pkt.transport_layer, 0) + 1
            else:
                countSans += 1
                dicSans[pkt.transport_layer] = dicSans.get(pkt.transport_layer, 0) + 1
        else :
            if i % 2 == 0:
                countSonNone += 1
                dicSon["None"] = dicSon.get("None", 0) + 1
            else:
                countSansNone += 1
                dicSans["None"] = dicSans.get("None", 0) + 1
    print(str(countTcp) + str(i))
for a in dicSon:
    dicSon[a] = (100*dicSon[a])/countSon
for a in dicSans:
    dicSans[a] = (100*dicSans[a])/countSans

dicSon = dict(sorted(dicSon.items(), key=lambda item: -item[1]))
dicSans = dict(sorted(dicSans.items(), key=lambda item: -item[1]))

labelsSon = dicSon.keys()
sizesSon = dicSon.values()

labelsSans = dicSans.keys()
sizesSans = dicSans.values()

fig1, ax1 = plt.subplots()
fig2, ax2 = plt.subplots()

#print(str(i))
ax1.pie(sizesSon, labels=labelsSon, autopct='%1.1f%%',
       pctdistance=0.8, labeldistance=1.1)
ax1.set_title("Proportion for cap sans tel")

ax2.pie(sizesSans, labels=labelsSans, autopct='%1.1f%%',
       pctdistance=0.8, labeldistance=1.1)
ax2.set_title("Proportion for cap avec tel")


fig1.savefig("Proportion for cap sans tel"+".svg", format="svg")
fig2.savefig("Proportion for cap avec tel"+".svg", format="svg")

plt.show()
#if ("DNS" in pkt):
    #print(pkt.dns)
#else :
    #print(pkt.layers[1])
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
dicSon = {}
countSon = 0
countSonNone = 0
dicVid = {}
countVid = 0
countVidNone = 0
for i in range(len(capts)):
    print("cap"+str(i)+":")

    cap = capts[i]
    countpkt=0
    for pkt in cap:
        countpkt+=1
        #print(pkt)
        if pkt.transport_layer != None:
            if i % 2 == 0:
                countSon += 1
                dicSon[pkt.transport_layer] = dicSon.get(pkt.transport_layer, 0) + 1
            else:
                countVid += 1
                dicVid[pkt.transport_layer] = dicVid.get(pkt.transport_layer, 0) + 1
        else :
            if i % 2 == 0:
                countSonNone += 1
                dicSon["None"] = dicSon.get("None", 0) + 1
            else:
                countVidNone += 1
                dicVid["None"] = dicVid.get("None", 0) + 1
    print(countpkt)
for a in dicSon:
    dicSon[a] = (100*dicSon[a])/countSon
for a in dicVid:
    dicVid[a] = (100*dicVid[a])/countVid

dicSon = dict(sorted(dicSon.items(), key=lambda item: -item[1]))
dicVid = dict(sorted(dicVid.items(), key=lambda item: -item[1]))

labelsSon = dicSon.keys()
sizesSon = dicSon.values()

labelsVid = dicVid.keys()
sizesVid = dicVid.values()

fig1, ax1 = plt.subplots()
fig2, ax2 = plt.subplots()

#print(str(i))
ax1.pie(sizesSon, labels=labelsSon, autopct='%1.1f%%',
       pctdistance=0.8, labeldistance=1.1)
ax1.set_title("Proportion de types de paquets sans vidéo")

ax2.pie(sizesVid, labels=labelsVid, autopct='%1.1f%%',
       pctdistance=0.8, labeldistance=1.1)
ax2.set_title("Proportion de types de paquets avec vidéo")


fig1.savefig("Proportion for cap Son"+".svg", format="svg")
fig2.savefig("Proportion for cap Video"+".svg", format="svg")

plt.show()
#if ("DNS" in pkt):
    #print(pkt.dns)
#else :
    #print(pkt.layers[1])

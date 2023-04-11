import pyshark
import numpy as np
import matplotlib.pyplot as plt
import tkinter as tk
import matplotlib
from varname import nameof
import subprocess

capts = []
cap0 = pyshark.FileCapture(r"C:\\Users\\Valentin\\Documents\\Etudes\\Q6.3\\Reseaux Informatiques\\TraceProjet\\EtV wVtwV appel simple 1.pcapng")
cap1 = pyshark.FileCapture(r"C:\\Users\\Valentin\\Documents\\Etudes\\Q6.3\\Reseaux Informatiques\\TraceProjet\\EtV wVtwV appel video 1.pcapng")
cap2 = pyshark.FileCapture(r"C:\\Users\\Valentin\\Documents\\Etudes\\Q6.3\\Reseaux Informatiques\\TraceProjet\\EtV 4GEt4GV appel simple 1.pcapng")
cap3 = pyshark.FileCapture(r"C:\\Users\\Valentin\\Documents\\Etudes\\Q6.3\\Reseaux Informatiques\\TraceProjet\\EtV 4GEt4GV appel video 1.pcapng")


capts.append(cap0)
capts.append(cap1)
capts.append(cap2)
capts.append(cap3)
dic = {}
count=0
for i in range(len(capts)):
    cap = capts[i]
    print("cap" + str(i) + ":")
    for pkt in cap:
        if "DNS" in pkt:
            #print(pkt.dns)
            #if str(pkt.dns.qry_class) != "0x0001": #internet
                #print(pkt.dns.qry_class)

            #print(pkt.dns.qry_type) # IPv4:1 ou IPv6 :28
            if(str(pkt.dns.flags_opcode)!="0"):
                print(pkt.flags_opcode) #0=standard query
            if(str(pkt.dns.qry_type) == "1"):
                dic["IPv4"] = dic.get("IPv4", 0) + 1
                count+=1
            elif (str(pkt.dns.qry_type) == "28"):
                dic["IPv6"] = dic.get("IPv6", 0) + 1
                count+=1
            else :
                dic[str(pkt.dns.qry_type)]=dic.get(str(pkt.dns.qry_type), 0) + 1
                count+=1
for a in dic:
    dic[a] = (100*dic[a])/count
#print(dic)
dic = dict(sorted(dic.items(), key=lambda item: -item[1]))
labels = dic.keys()
sizes = dic.values()
fig, ax = plt.subplots()

ax.pie(sizes, labels=labels, autopct='%1.1f%%',
       pctdistance=0.8, labeldistance=1.1,radius=1.3)
ax.set_title("Proportion de types de requêtes DNS", pad=20)
plt.savefig("Proportion of DNS query type.svg", format="svg")
plt.show()



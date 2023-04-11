import pyshark
import numpy as np
import matplotlib.pyplot as plt
import tkinter as tk
import matplotlib
from varname import nameof
import subprocess


def getSOA(domainName):
    tempo = subprocess.check_output('cmd /c "nslookup -type=soa ' + domainName + '"')
    if (len(str(tempo)) > 55):
        return str(tempo).split("primary name server = ")[1].split("responsible mail addr = ")[0].split("\\")[0]
    else:
        return "Non-existent domain"


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
dic = {}
for i in range(len(capts)):
    cap = capts[i]
    print("cap" + str(i) + ":")
    with open("ListOfDNSNameCap" + str(i) + ".txt", 'w') as f:
        with open("ListOfQuery-A-Domaincap" + str(i) + ".txt", 'w') as g:
            for pkt in cap:
                if "DNS" in pkt:
                    # print(pkt.dns.flags_response)
                    # print(pkt.dns
                    # print(str(i))
                    if (pkt.dns.flags_response == str(1)):
                        # print(pkt.dns.flags_authoritative)
                        if (pkt.dns.count_auth_rr != str(1)):
                            a = 1  # print(pkt.dns)
                        # print(pkt.dns.count_auth_rr)
                        # if (pkt.dns.flags_authoritative != str(0)):
                        # print(pkt.dns)
                        # print(pkt.dns.field_names)
                        if (pkt.dns.flags_rcode == str(0)):
                            f.write(str(pkt.dns.count_queries) + " " + str(
                                pkt.dns.count_answers + " " + str(pkt.dns.count_auth_rr) + "||"))
                            # print(str(pkt.dns.flags_authoritative))
                            for k in range(int(pkt.dns.count_queries)):
                                f.write(pkt.dns.resp_name + "||")

                                for l in range(int(pkt.dns.count_answers)):
                                    f.write(" " + str(pkt.dns.cname) + "|")
                                    # print(str(pkt.dns.cname))
                            f.write("\n")
                        else:
                            f.write(str(pkt.dns.qry_name + " error" + "\n"))
                    else:
                        # print(pkt.dns.qry_name)
                        # print(dic)
                        # print([str(pkt.dns.qry_name)])
                        if str(pkt.dns.qry_name) not in dic.get(str(getSOA(pkt.dns.qry_name)), []):
                            dic[str(getSOA(pkt.dns.qry_name))] = dic.get(str(getSOA(pkt.dns.qry_name)), []) + [
                                str(pkt.dns.qry_name)]
                        # g.write(str(pkt.dns.qry_name)+" | "+getSOA(pkt.dns.qry_name)+"\n")
                        # print(getSOA(pkt.dns.qry_name))
                    # print(pkt.dns.resp_name)
                # print(pkt.layers)
                # if "UDP" in pkt.layers:
                #    print(pkt.udp)
                #    if "DNS" in pkt.udp:
                #        print("detected udp")
                # if "TCP" in pkt.layers:
                #    print(pkt.tcp)
                #    if "DNS" in pkt.tcp:
                #        print("detected tcp")
                # print(nameof(a))
                # print(pkt.dns.qry)
                # print(pkt.dns.resp_name)
# print(dic)
with open("ListAuthoritative.txt", 'w') as LA:
    for i in dic:
        LA.write(str(i) + " :\n")
        for j in dic[i]:
            LA.write("\t" + str(j) + "\n")
    LA.write("\n")

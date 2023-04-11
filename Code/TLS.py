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
#dic = {}
#countTLS = 0

dicTLS0 = {}
countTLS0 = 0

dicTLS2 = {}
countTLS2 = 0

dicCipher={}
countCipher=0

#dicTLS3 = {}
#countTLS3 = 0
for i in range(len(capts)):
    cap = capts[i]
    print("cap" + str(i) + ":")
    for pkt in cap:
        if "TLS" in pkt:
            #try :
            #    print(pkt.tls.field_names)
            #except:
            #    pass
            #try :
                #print(pkt.transport_layer)
                #print(pkt.get_multiple_layers("http"))
            #    a=1
            #except:
            #    pass
            #print(pkt.tls)
            #print(pkt.tls.field_names)
            #print(pkt.tls.record_version)
            try:
                #dic[pkt.tls.record_version] = dic.get(pkt.tls.record_version, 0) + 1
                #countTLS += 1
                #print(str(pkt.tls.record_version))
                #print(str(0x0301))
                if str(pkt.tls.record_version) == "0x0303":


                    if str(pkt.tls.app_data_proto) == "Hypertext Transfer Protocol":
                        dicTLS2["HTTP"] = dicTLS2.get("HTTP", 0) + 1
                    elif str(pkt.tls.app_data_proto) == "HyperText Transfer Protocol 2":
                        dicTLS2["HTTP 2"] = dicTLS2.get("HTTP 2", 0) + 1
                    elif str(pkt.tls.app_data_proto) == "MQ Telemetry Transport Protocol":
                        dicTLS2["MQ TTP"] = dicTLS2.get("MQ TTP", 0) + 1
                    else:
                        #print(str(pkt.tls.app_data_proto))
                        a=1
                    countTLS2 += 1

                if str(pkt.tls.record_version) == "0x0301":
                    #print("coucou")
                    #print(pkt.tls.field_names)
                    #print(pkt.tls.record_content_type)
                    #print(pkt.tls.handshake)
                    #print(pkt.tls.handshake_type)
                    dicTLS0[str(pkt.tls.app_data_proto)] = dicTLS0.get(str(pkt.tls.app_data_proto), 0) + 1
                    countTLS0 += 1
                if pkt.tls.record_version != "0x0301" and pkt.tls.record_version != "0x0303":
                    #print(pkt.tls.record_version)
                    b=2
            except:
                pass
            try:
                1+1
                #print(pkt.tls.handshake_type)
            except:
                pass
            try :
                #print(pkt.tls.handshake_ciphersuite)
                if "0xc030"==str(pkt.tls.handshake_ciphersuite):
                    dicCipher["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"] = dicTLS0.get("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", 0) + 1
                elif "0xc02c"==str(pkt.tls.handshake_ciphersuite):
                    dicCipher["TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"] = dicTLS0.get("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", 0) + 1
                elif "0xaaaa" == str(pkt.tls.handshake_ciphersuite):
                    dicCipher["TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"] = dicTLS0.get(
                        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", 0) + 1


                else:
                    print(pkt.tls.handshake_ciphersuite)
            except:
                pass
            try :
                1 + 1
                #print(pkt.tls.handshake_version)
            except:
                pass
            try :
                1 + 1
                #print(pkt.tls.compress_certificate_algorithm)
            except:
                pass
            try :
                #print(pkt.tls.handshake_certificate)
                1 + 1
            except:
                pass



#print(dicTLS0)
#print(dicTLS2)


for a in dicTLS2:
    dicTLS2[a] = (100*dicTLS2[a])/countTLS2

dicTLS2 = dict(sorted(dicTLS2.items(), key=lambda item: -item[1]))


labels = dicTLS2.keys()
sizes= dicTLS2.values()


fig, ax = plt.subplots()


#print(str(i))
ax.pie(sizes, labels=labels, autopct='%1.1f%%',
       pctdistance=0.8, labeldistance=1.1,radius=1.3, textprops={'size': 'smaller'})
ax.set_title("Proportion de protocols de transports utilisés",pad=20)




fig.savefig("Proportion de protocols de transports utilises"+".svg", format="svg")


plt.show()
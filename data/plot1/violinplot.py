#!/usr/bin/env python

import seaborn 
import matplotlib.pyplot as plt 
import sys
import pandas

count = 0
headers = []
name= ["TLS 1.3", "KEMTLS-IBE-PDK", "KEMTLS-IBE", "KEMTLS-IBE-MPK", "A", "B"]
dirs = ["local_new_0_0", "local_new_1_0", "local_new_5_0", "local_new_50_0", "local_new_150_0", "linode_google"]
files = ["tls-client.csv", "pdk.csv", "our.csv", "mpk.csv"]
latency = ["Latency: 0ms", "Latency: 1ms", "Latency: 5ms", "Latency: 50ms", "Latency: 150ms", "Real Network"]
data = {}

# DIR escolhido:
for n in 0, 1, 2, 3, 4, 5:
    title = latency[n]
    i=0
    for filename in files:
        with open(dirs[n] + "/" + filename) as file:
            data[name[i]] = []
            if i >= 2:
                data[name[i+2]] = []
            print(dirs[n] + "/" + files[i])
            count = 0
            while line := file.readline():
                if count != 0: # Ignora primeira linha
                    lin = line.rstrip().split(",")
                    data[name[i]].append(float(lin[1]))
                    if i >= 2:
                        data[name[i+2]].append(float(lin[2]))
                count = count + 1
            i = i + 1 # Proximo arquivo
        
    seaborn.set(style = 'whitegrid')
    df = pandas.DataFrame.from_dict(
        data=dict(A=data[name[0]], B=data[name[1]], C=data[name[2]], D=data[name[3]], E=data[name[4]], F=data[name[5]]),
        orient='index',
    ).T
    p=seaborn.violinplot(data=df)
    p.set_title(title, fontsize=20)
    p.set_xticklabels(["TLS 1.3\n(Handshake Time)", "KEMTLS-IBE-PDK\n(Handshake Time)", "KEMTLS-IBE\n(Handshake Time)", "KEMTLS-IBE-MPK\n(Handshake Time)", "KEMTLS-IBE\n(SendApp Time)", "KEMTLS-IBE-MPK\n(SendApp Time)"])
    plt.axvline(3.5, 0,1000)
    p.set_yticks(p.get_yticks()[1:])
    p.set_yticklabels(p.get_yticks(), size = 12)
    plt.tight_layout()
    fig = p.get_figure()
    fig.set_figheight(10.0)
    fig.set_figwidth(10.0)
    fig.savefig(str(n) + ".png")
    plt.close()


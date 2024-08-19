#!/usr/bin/env python

import seaborn 
import matplotlib.pyplot as plt 
import sys
import pandas

count = 0
headers = []
name= ["TLS 1.3", "KEMTLS-IBE-PDK", "KEMTLS-IBE", "KEMTLS-IBE-MPK", "A", "B"]
dirs = ["local_new_50_0", "local_new_150_0", "linode_google"]
files = ["tls-client.csv", "pdk.csv", "our.csv", "mpk.csv"]
latency = ["Latency: "]
a = [190, 610, 190]
b = [90, 300, 90]
s = [30, 30, 30]


data = {}

# DIR escolhido:
for n in 0, 1, 2:
    title = "Real Network"
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
    f, (ax1, ax2) = plt.subplots(ncols=1, nrows=2)
    p1=seaborn.violinplot(data=df, ax=ax1)
    p2=seaborn.violinplot(data=df, ax=ax2)
    ax1.set_ylim(a[n], a[n]+s[n])
    ax2.set_ylim(b[n],b[n]+s[n])
    seaborn.despine(ax=ax1)
    seaborn.despine(ax=ax2, bottom=True)
    d = .015
    kwargs = dict(transform=ax1.transAxes, color='k', clip_on=False)
    ax1.plot((-d, +d), (-d, +d), **kwargs)        # top-left diagonal
    kwargs.update(transform=ax2.transAxes)  # switch to the bottom axes
    ax2.plot((-d, +d), (1 - d, 1 + d), **kwargs)  # bottom-left diagonal
    p1.set_xticklabels([])
    p2.set_xticklabels(["TLS 1.3\n(Handshake Time)", "KEMTLS-IBE-PDK\n(Handshake Time)", "KEMTLS-IBE\n(Handshake Time)", "KEMTLS-IBE-MPK\n(Handshake Time)", "KEMTLS-IBE\n(SendApp Time)", "KEMTLS-IBE-MPK\n(SendApp Time)"])
    p1.set_yticks(p1.get_yticks()[1:])
    p1.set_yticklabels(p1.get_yticks(), size = 20)
    p2.set_yticks(p2.get_yticks()[1:])
    p2.set_yticklabels(p2.get_yticks(), size = 20)
    p1.set_title(title, fontsize=20)
    p1.axvline(3.5, 0,1000)
    p2.axvline(3.5, 0,1000)
    plt.tight_layout()
    fig = f.get_figure()
    fig.set_figheight(10.0)
    fig.set_figwidth(10.0)
    fig.savefig(str(4+n) + ".png") 

#plt.show()


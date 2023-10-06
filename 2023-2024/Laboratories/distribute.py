#!/usr/bin/python3
import subprocess

rpinums = range(0, 47)
for rpi in rpinums:
    rpistr = "rpi4-{0:03d}.advopsys.cl.cam.ac.uk".format(rpi)
    print(rpistr + ":")

    cmdstr = ["ssh", "root@" + rpistr, "rm -Rf /advopsys"]
    output = subprocess.run(cmdstr)
    cmdstr = ["ssh", "root@" + rpistr, "rm -Rf /advopsys-packages/labs"]
    output = subprocess.run(cmdstr)
    cmdstr = ["ssh", "root@" + rpistr, "mkdir -p /advopsys-packages/labs"]
    output = subprocess.run(cmdstr)
    cmdstr = ["scp", "2022-2023-advopsys-lab1.tbz",
      "2022-2023-advopsys-lab2.tbz", "2022-2023-advopsys-lab3.tbz",
      "root@" + rpistr + ":/advopsys-packages/labs/"]
    output = subprocess.run(cmdstr)

#!/usr/bin/python3
import subprocess

rpinums = range(0, 47)
for rpi in rpinums:
    rpistr = "rpi4-{0:03d}.advopsys.cl.cam.ac.uk".format(rpi)
    print(rpistr + ":")

    cmdstr = ["ssh", "root@" + rpistr, "rm -Rf /advopsys/labs"]
    output = subprocess.run(cmdstr)
    cmdstr = ["ssh", "root@" + rpistr, "mkdir -p /advopsys/labs"]
    output = subprocess.run(cmdstr)
    cmdstr = ["scp", "2021-2022-advopsys-lab1.tbz",
      "2021-2022-advopsys-lab2.tbz", "root@" + rpistr + ":/advopsys/labs/"]
    output = subprocess.run(cmdstr)

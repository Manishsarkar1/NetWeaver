



from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel
import random
import time
import os

TRIGGER_FILE = "/tmp/mtd_trigger"

def random_ip():
    return f"10.0.0.{random.randint(10, 250)}"

def run():
    net = Mininet(
        controller=RemoteController,
        switch=OVSSwitch,
        build=False
    )

    c0 = net.addController("c0", ip="127.0.0.1", port=6653)
    s1 = net.addSwitch("s1")

    h1 = net.addHost("h1", ip="10.0.0.1/24")
    h2 = net.addHost("h2", ip="10.0.0.2/24")
    h3 = net.addHost("h3", ip="10.0.0.3/24")

    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)

    net.build()
    net.start()

    print("[✓] Network started")

    def mtd_loop():
        last = 0
        while True:
            if os.path.exists(TRIGGER_FILE):
                t = float(open(TRIGGER_FILE).read())
                if t != last:
                    last = t
                    print("\n[MTD] Reassigning IPs")

                    for h in [h1, h2, h3]:
                        new_ip = random_ip()
                        h.cmd(f"ifconfig {h.defaultIntf()} {new_ip}/24")
                        h.cmd("ip neigh flush all")
                        print(f" {h.name} → {new_ip}")

            time.sleep(1)

    from threading import Thread
    Thread(target=mtd_loop, daemon=True).start()

    CLI(net)
    net.stop()

if __name__ == "__main__":
    setLogLevel("info")
    run()


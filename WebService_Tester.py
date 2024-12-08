from spyne import Application, rpc, ServiceBase, Unicode
from spyne.protocol.soap import Soap11
from spyne.server.wsgi import WsgiApplication
from wsgiref.simple_server import make_server
import logging
from datetime import datetime
import io
from lxml import etree
import socket
import serial
import time
import binascii
import serial.tools.list_ports
import threading
import logging 
import tkinter as tk
import requests
import json

# 版本號
VERSION = 'V0.4'

# 獲取本機 IP 地址
def get_local_ip():
    try:
        # 獲取所有網路介面
        ip_list = []
        for interface in socket.getaddrinfo(socket.gethostname(), None):
            ip = interface[4][0]
            # 只取 IPv4 地址且不是 localhost
            if '.' in ip and ip != '127.0.0.1':
                ip_list.append(ip)
        # 如果有找到 IP，返回第一個
        return ip_list[0] if ip_list else "127.0.0.1"
    except Exception as e:
        logger.error(f"獲取 IP 地址時發生錯誤: {str(e)}")
        return "127.0.0.1"

# 服務配置
HOST = get_local_ip()
PORT = 8000
SERVICE_URL = f"http://{HOST}:{PORT}/CP_Auto_Service/WIP_rack_Service.asmx"

# 設置日誌檔案名稱
log_filename = f'ws_tester_{datetime.now().strftime("%Y%m%d")}.txt'

# 設置日誌
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),  # 輸出到控制台
        logging.FileHandler(log_filename, encoding='utf-8')  # 輸出到檔案
    ]
)
logger = logging.getLogger('wiprack_service')

def element_to_string(element):
    """將 XML 元素轉換為格式化的字串"""
    return etree.tostring(element, pretty_print=True, encoding='unicode')

# 建立自定義的SOAP協議類來記錄請求和回應
class LoggingSoap11(Soap11):
    def create_in_document(self, ctx, charset=None):
        logger.info(f"\n[{datetime.now()}] 收到請求:")
        # 記錄請求標頭
        if hasattr(ctx.transport, 'req_env'):
            headers = {k: v for k, v in ctx.transport.req_env.items() if k.startswith('HTTP_')}
            logger.info(f"請求標頭: {headers}")
            logger.info(f"請求方法: {ctx.transport.req_env.get('REQUEST_METHOD')}")
            logger.info(f"請求路徑: {ctx.transport.req_env.get('PATH_INFO')}")
        
        # 記錄請求內容
        if hasattr(ctx, 'in_string'):
            try:
                # 保存原始輸入
                original_input = ctx.in_string

                # 讀取內容
                if isinstance(original_input, (bytes, str)):
                    content = original_input
                elif hasattr(original_input, 'read'):
                    content = original_input.read()
                else:
                    content = b''.join(original_input)

                # 解碼並記錄
                if isinstance(content, bytes):
                    decoded_content = content.decode('utf-8')
                else:
                    decoded_content = str(content)
                logger.info(f"請求內容: {decoded_content}")

                # 如果是字串，轉換為位元組
                if isinstance(content, str):
                    content = content.encode('utf-8')

                # 創建一個新的位元組流
                ctx.in_string = io.BytesIO(content)

            except Exception as e:
                logger.error(f"處理請求內容時發生錯誤: {str(e)}")
                raise

        return super().create_in_document(ctx, charset)

    def create_out_string(self, ctx, charset=None):
        result = super().create_out_string(ctx, charset)
        
        try:
            logger.info(f"\n[{datetime.now()}] 發送回應:")
            
            # 記錄應用程序回應
            if hasattr(ctx, 'out_document') and ctx.out_document is not None:
                try:
                    xml_string = element_to_string(ctx.out_document)
                    logger.info(f"回應內容:\n{xml_string}")
                except Exception as e:
                    logger.info(f"回應內容: {ctx.out_document}")
            
            # 記錄序列化後的回應
            if result:
                if isinstance(result, (list, tuple)):
                    response_content = b''.join(result)
                else:
                    response_content = result
                
                if isinstance(response_content, bytes):
                    response_content = response_content.decode('utf-8')
                logger.info(f"序列化回應:\n{response_content}")
            
        except Exception as e:
            logger.error(f"處理回應內容時發生錯誤: {str(e)}")
        
        return result

    def fault_to_string(self, ctx, charset=None):
        result = super().fault_to_string(ctx, charset)
        
        try:
            logger.info(f"\n[{datetime.now()}] 發送錯誤回應:")
            if result:
                if isinstance(result, bytes):
                    error_content = result.decode('utf-8')
                else:
                    error_content = str(result)
                logger.info(f"錯誤內容:\n{error_content}")
        except Exception as e:
            logger.error(f"處理錯誤回應時發生錯誤: {str(e)}")
        
        return result

class WIPRackService(ServiceBase):
    __service_url__ = SERVICE_URL  # 設置服務 URL
    
    @rpc(_returns=Unicode)
    def HelloWorld(ctx):
        return '{"Hello World": "Hello World"}'

    @rpc(Unicode, _returns=Unicode)
    def GET_WIPRACK_TRANSFER(ctx, Param):
        # 在此實現獲取 WIP rack 轉移信息的業務邏輯
        # FIXME: 處理 {Param} 參數 & 回傳正確資訊，目前先回傳固定字串
        return f'{Param}'

    @rpc(Unicode, _returns=Unicode)
    def Status_Change(ctx, Param):
        # 在此實現狀態更改的業務邏輯
        # FIXME: 處理 {Param} 參數 & 回傳正確資訊，目前先回傳固定字串
        return '''{
            "Status": "0",
            "StatusMsg": "fail , 詢問儲格狀態逾時"
        }'''

    @rpc(Unicode, _returns=Unicode)
    def WIPRACK_Info(ctx, Param):
        global wiprack 
        # 在此實現獲取 WIP rack 信息的業務邏輯
        # FIXME: 處理 {Param} 參數 & 回傳正確資訊，目前先回傳固定字串
        wiprack = []
        for i in range(2):
            for j in range(15):
                row, column = label_positions[(i, j)]
            
            # 當 USB_BUS 不存在或未開啟
                if not USB_BUS or not USB_BUS.is_open:
                    cassette_status = {'Status': '0', 'StatusMsg': 'FAIL'}
                    cassette = {
                        'CURR_DEV': 'WipRack01',
                        'CURR_LOC': f"{row}_{column}",
                        'CASSETTEID': labels[i][j]['text']
                    }
                else:
                    bg_color = labels[i][j].cget('bg')
                
                    if bg_color == 'green':  # 綠色背景
                        cassette_status = {'Status': '1', 'StatusMsg': 'PASS'}
                        cassette = {
                            'CURR_DEV': 'WipRack01',
                            'CURR_LOC': f"{row}_{column}",
                            'CASSETTEID': labels[i][j]['text'],
                            'LOC_STATE': '0'
                        }
                    elif bg_color == 'gray':  # 灰色背景
                        cassette_status = {'Status': '1', 'StatusMsg': 'PASS'}
                        cassette = {
                            'CURR_DEV': 'WipRack01',
                            'CURR_LOC': f"{row}_{column}",
                            'CASSETTEID': labels[i][j]['text'],
                            'LOC_STATE': '1'
                        }
                    
            # 每次迴圈都把 cassette 加入 wiprack 列表
                wiprack.append(cassette)
    
        return f'''{cassette_status,wiprack}'''

application = Application(
    [WIPRackService],
    tns='http://tempuri.org/',
    in_protocol=LoggingSoap11(validator='lxml'),
    out_protocol=LoggingSoap11(validator='lxml'),
    name='WIP_rack_Service'
)

# 自定義 WSGI 應用程序類來處理特定路徑
class INIKIWipRackWsgiApplication(WsgiApplication):
    def __call__(self, environ, start_response):
        path = environ.get('PATH_INFO', '').rstrip('/')
        
        # 只允許 /INIKIWipRack 路徑
        if path != '/INIKIWipRack':
            # 記錄非法請求
            logger.warning(f"收到非法路徑請求: {path}")
            
            # 返回 404 錯誤
            status = '404 Not Found'
            response_headers = [('Content-type', 'text/plain; charset=utf-8')]
            start_response(status, response_headers)
            return [b'404 Not Found: Invalid path']
            
        environ['PATH_INFO'] = '/INIKIWipRack'
        return super().__call__(environ, start_response)
def start_server():
    wsgi_app = INIKIWipRackWsgiApplication(application)
    server = make_server('0.0.0.0', PORT, wsgi_app)
    logger.info(f"WIP Rack Service {VERSION} 啟動")
    print(f"WIP Rack Service {VERSION} 服務已啟動")
    print(f"WSDL 文件位址: http://{HOST}:{PORT}/INIKIWipRack?wsdl")
    server.serve_forever() 
wsgi_application = WsgiApplication(application)

def create_soap_message(CASSETTEID):
    soap_message = f"""<?xml version="1.0" encoding="utf-8"?>
    <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" 
                   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
                   xmlns:xsd="http://www.w3.org/2001/XMLSchema">
      <soap:Body>
        <GET_WIPRACK_TRANSFER xmlns="http://tempuri.org/">
          <Param>{CASSETTEID}</Param>
        </GET_WIPRACK_TRANSFER>
      </soap:Body>
    </soap:Envelope>"""
    return soap_message

# 发送 SOAP 消息
def send_message_wip_transfer(CASSETTEID):
    global  CONNECTING_bottom_left_label
    # 使用鎖來保護這段代碼
    with lock:
        start_time = time.time()  # 紀錄開始時間
        duration = 0.01  # 設定執行時間（秒）

        while time.time() - start_time < duration:
            # 只在1秒內執行
            time.sleep(0.01)
            try:
                soap_message = create_soap_message(CASSETTEID)  # 生成SOAP消息
                headers = {
                    'Content-Type': 'text/xml; charset=utf-8',
                    'SOAPAction': '"http://tempuri.org/GET_WIPRACK_TRANSFER"'
                }
                response = requests.post("http://192.168.1.44:8000/WIP_rack_Service.asmx/GET_WIPRACK_TRANSFER",
                                         data=soap_message, headers=headers)
                if response.status_code == 200:
                    CONNECTING_bottom_left_label['text'] = 'RESPONSE SUCCESS'
                    logging.info(f"Client sent message, Server responded: {response.content}")
                    None
                else:
                    CONNECTING_bottom_left_label['text'] = 'RESPONSE FAIL'
                    logging.error(f"Failed to get a valid response. Status code: {response.status_code}")
                    None
            except Exception as e:
                logging.error(f"Failed to send message: {e}")
                None

"""嘗試連接"""
def connect_USB_BUS():
    try:
        ports = serial.tools.list_ports.comports()
        if not ports:
            #print("沒有找到可用端口")
            None
        for port in ports:
            if  "USB" in port.description:  # USB_BUS 的端口名稱可能會有所不同
                USB_BUS = serial.Serial(port.device,57600, timeout=1)
                #USB_BUS.dtr = True
                #time.sleep(0.01)
                #USB_BUS.dtr = False
                #time.sleep(3)  # 等待 USB_BUS 初始化，延長等待時間以確保連接穩定
                return USB_BUS
    except serial.SerialException as e:
        print(f"串口連接失敗: {e}")
        return None
    return None


'''SEND COMMAND'''
def send_hex_command(USB_BUS, hex_command):

    if not USB_BUS:
        #print('USB 未連接')
        return None
    try:
        command_bytes = bytes.fromhex(hex_command)
        USB_BUS.read(USB_BUS.in_waiting)  # 清除緩衝區中的剩餘數據
        USB_BUS.write(command_bytes)  # 發送命令
        time.sleep(0.02)
        USB_BUS.flush()
        start_time = time.time()
        while USB_BUS.in_waiting < 360:  # 等待完整的12字節回應
            if time.time() - start_time > 2:
                #print("TimeSpend: ",time.time() - start_time)
                return None
        #print("TimeSpend: ",time.time() - start_time)
        if USB_BUS.in_waiting == 360:
            response_bytes = USB_BUS.read(360)  # 讀取12字節的回應
            for i in range(360):
                if response_bytes[i] != 0:
                    return response_bytes
            return None  # 返回 None 來表示 "empty"
        else:
            #print('USB buffer len: ',USB_BUS.in_waiting)
            #print('Get msg: ',USB_BUS.read(USB_BUS.in_waiting))
            return None
    except (serial.SerialException, OSError) as e:
        print(f'通信錯誤: {e}')
        USB_BUS.close()
        return None

def send_wiprack_hex_command(USB_BUS, hex_command):
    if not USB_BUS:
        #print('USB 未連接')
        return None

    try:
        # 將 16 進制命令轉換為位元組
        command_bytes = bytes.fromhex(hex_command)
        USB_BUS.read(USB_BUS.in_waiting)  # 清空緩衝區中的剩餘資料
        USB_BUS.write(command_bytes)  # 發送命令
        time.sleep(0.02)
        USB_BUS.flush()
        start_time = time.time()  # 記錄開始時間
        # 等待 2 秒來接收回應數據
        while time.time() - start_time < 2:
            if USB_BUS.in_waiting > 0:  # 檢查是否有資料可讀
                response_byte = USB_BUS.read(1)  # 只讀取 1 字節
                hex_value = response_byte.hex()  # 轉換為 16 進制字符串
                decimal_value = int(hex_value, 16)  # 將 16 進制轉為 10 進制
                #print(f"Received 1 byte: {hex_value} (hex) => {decimal_value} (decimal)")  # 打印 16 進制和 10 進制
                return decimal_value

        print("超時，未接收到任何資料")
        return None
    except (serial.SerialException, OSError) as e:
        print(f'通信錯誤: {e}')
        USB_BUS.close()
        return None

    except (serial.SerialException, OSError) as e:
        print(f'通信錯誤: {e}')
        USB_BUS.close()
        return None

'''hex_data to ASCII'''
def hex_to_ascii(hex_data):
    try:
        # 解析接收到的資料，如果長度正確並且有效
        if hex_data and len(hex_data) % 2 == 0:
            return binascii.unhexlify(hex_data).decode('ascii', errors='replace')
        else:
            return '資料格式不正確'
    except (TypeError, binascii.Error) as e:
        print(f'解碼錯誤: {e}')
        logging.error(f"解碼錯誤: {e}")
        return '解碼錯誤'
def is_valid_ascii(char):
    # 如果传入的是整数类型的 ASCII 码，直接比较范围
    if isinstance(char, int):
        if (48 <= char <= 57) or (65 <= char <= 90) or (97 <= char <= 122) or char == 0:
            return True
        else:
            return False
    # 否则，假设传入的是字符类型，使用 ord() 获取 ASCII 值进行比较
    elif isinstance(char, str) and len(char) == 1:
        ascii_value = ord(char)
        if (48 <= ascii_value <= 57) or (65 <= ascii_value <= 90) or (97 <= ascii_value <= 122) or ascii_value == 0:
            return True
        else:
            return False
    return False  # 如果既不是整数也不是单字符字符串，则返回 False

# 示例：检查一个字符串
def validate_string(text):
    for char in text:
        if not is_valid_ascii(char):
            return False  # 一旦发现不符合条件的字符，返回 False
    return True  # 所有字符都符合条件时返回 True
def RGB_LIGHT(rgb_light_type, i, j):
    if USB_BUS and USB_BUS.is_open:
        addr = i * 15 + j + 1  # 計算 addr
        if addr > 30:
            addr = 30
        elif addr < 0:
            addr = 0
            
        try:
            # 插入 addr 到對應的位置，並將其轉換為兩位的十六進位字串
            if rgb_light_type == 1:
                RGB_command = '94 6B 12 {:02X} 00 00 00'.format(addr)  # 無色
            elif rgb_light_type == 2:
                RGB_command = '94 6B 12 {:02X} FF FF 00'.format(addr)  # 黃色
            elif rgb_light_type == 3:
                RGB_command = '94 6B 12 {:02X} 00 FF 00'.format(addr)  # 綠色
            else:
                RGB_command = '94 6B 12 {:02X} FF 00 00'.format(addr)  # 紅色

            # 將字串轉換為 byte
            RGB_command_bytes = bytes.fromhex(RGB_command)
            
            # 發送指令
            USB_BUS.write(RGB_command_bytes)
            USB_BUS.flush()
            #time.sleep(0.06)
            # 檢查緩衝區，確保緩衝區已清空
           # while USB_BUS.out_waiting > 0:
                #pass  # 等待緩衝區被清空
            #print("指令已成功发送")
        except (TypeError, binascii.Error) as e:
            print(f"串口通信错误: {e}")
            USB_BUS.close()
    else:
        #print("USB 端口未打开或连接失败")
        None
'''initial setting'''
USB_BUS = None
lock = threading.Lock()
hex_command = ['94 6B 02']# command send
light_hex_command = ['94 6B 11 01 00 00 00','94 6B 11 00 01 00 00','94 6B 11 00 00 01 00']
wiprack_hex_command = ['94 6B 05']
wiprack_data = ['']
data = ['']
data_cut = [[None for _ in range(15)] for _ in range(2)]
labels = [[] for _ in range(2)]
previous_data_cut=[[b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' for _ in range(15)] for _ in range(2)]
let_target_label_maintain_yellow = [[None for _ in range(15)] for _ in range(2)]
target = ''
USB_DIS = 0
split_length =12#cut into 30 pieces 30x12=360
label_positions = {
    (0, 0): (1, 1), (0, 1): (1, 2), (0, 2): (1, 3), (0, 3): (1, 4), (0, 4): (1, 5), 
    (0, 5): (1, 6), (0, 6): (1, 7), (0, 7): (1, 8), (0, 8): (1, 9), (0, 9): (1, 10),
    (0, 10): (2, 1), (0, 11): (2, 2), (0, 12): (2, 3), (0, 13): (2, 4), (0, 14): (2, 5),
    (1, 0): (2, 6), (1, 1): (2, 7), (1, 2): (2, 8), (1, 3): (2, 9), (1, 4): (2, 10),
    (1, 5): (3, 1), (1, 6): (3, 2), (1, 7): (3, 3), (1, 8): (3, 4), (1, 9): (3, 5),
    (1, 10): (3, 6), (1, 11): (3, 7), (1, 12): (3, 8), (1, 13): (3, 9), (1, 14): (3, 10),
}

'''trigger event'''
def event_label(event):
    global target
    target= Searching_Event.get()+'\x00'*4
'''creat label windows'''
root = tk.Tk()
root.title("Service Interface")
root.attributes("-fullscreen", True)  # 全屏显示
# 为行列设置权重，确保网格单元均匀分布
for i in range(6):
    root.grid_rowconfigure(i,  minsize=120)  # 行均匀分布*樹梅派150
for j in range(5):
    root.grid_columnconfigure(j,  minsize=150)  # 列均匀分布*樹梅派365

# 搜索输入框置中显示，占用3列
Searching_Event = tk.Entry(root, show=None, font=('Arial', 25))
Searching_Event.grid(row=6, column=1, columnspan=3, pady=20, sticky="n")  # column=1 跨3列

Searching_Event = tk.Entry(root, show=None, font=('Arial', 25))
Searching_Event.grid(row=6, column=0, columnspan=5, pady=20)

frame = tk.Frame(root)
frame.grid(row=0, column=0, padx=10, pady=20)

frame_group_1 = tk.Frame(root, borderwidth=5, relief="solid")
frame_group_1.grid(row=0, column=0, rowspan=2, columnspan=5, padx=1,  pady=(30, 5),sticky="nsew")

frame_group_2 = tk.Frame(root, borderwidth=5, relief="solid")
frame_group_2.grid(row=2, column=0, rowspan=2, columnspan=5, padx=1, pady=(30, 5), sticky="nsew")

frame_group_3 = tk.Frame(root, borderwidth=5, relief="solid")
frame_group_3.grid(row=4, column=0, rowspan=2, columnspan=5, padx=1, pady=(30, 5), sticky="nsew")


# 初始化标签框架
labels = [[], []]  # labels[0] 对应前3行，labels[1] 对应后3行

# 创建6x5的标签网格
for i in range(6):
    for j in range(5):
        label_text = f"{(i // 2 + 1)}-{(j * 2 + (1 if i % 2 == 0 else 2))}"  # 根据你的逻辑设置标签文本
        label = tk.Label(root, text=label_text, borderwidth=1, relief="solid", anchor="center", font=('Arial', 20, 'bold'),width=16, height=2)
        label.grid(row=i, column=j, padx=5, pady=(35, 10), sticky="nsew")  # 使用 sticky="nsew" 让标签充满单元格
        if i <= 2:
            labels[0].append(label)
        else:
            labels[1].append(label)
for i in range(6):
    if i == 0 :
        new_label = tk.Label(root, text=f"LAYER1 FRONT", borderwidth=1, relief="solid", anchor="center", font=('Arial', 15, 'bold'),wraplength=100)
        new_label.grid(row=i, column=5, padx=5, pady=(35, 10), sticky="nsew")  # 手动添加到第6列 (column=5)\
    elif i==1:
        new_label = tk.Label(root, text=f"LAYER1 REAR", borderwidth=1, relief="solid", anchor="center", font=('Arial', 15, 'bold'),wraplength=100)
        new_label.grid(row=i, column=5, padx=5, pady=(35, 10), sticky="nsew",)  # 手动添加到第6列 (column=5)\
    elif i==2:
        new_label = tk.Label(root, text=f"LAYER2 FRONT", borderwidth=1, relief="solid", anchor="center", font=('Arial', 15, 'bold'),wraplength=100)
        new_label.grid(row=i, column=5, padx=5, pady=(35, 10), sticky="nsew")  # 手动添加到第6列 (column=5)\
    elif i==3:
        new_label = tk.Label(root, text=f"LAYER2 REAR", borderwidth=1, relief="solid", anchor="center", font=('Arial', 15, 'bold'),wraplength=100)
        new_label.grid(row=i, column=5, padx=5, pady=(35, 10), sticky="nsew")  # 手动添加到第6列 (column=5)\
    elif i==4:
        new_label = tk.Label(root, text=f"LAYER3 FRONT", borderwidth=1, relief="solid", anchor="center", font=('Arial', 15, 'bold'),wraplength=100)
        new_label.grid(row=i, column=5, padx=5, pady=(35, 10), sticky="nsew",)  # 手动添加到第6列 (column=5)\
    else:
        new_label = tk.Label(root, text=f"LAYER3 REAR", borderwidth=1, relief="solid", anchor="center", font=('Arial', 15, 'bold'),wraplength=100)
        new_label.grid(row=i, column=5, padx=5, pady=(35, 10), sticky="nsew")  # 手动添加到第6列 (column=5)\
def update_time():
    current_time = time.strftime('%H:%M:%S')  # 获取当前时间
    time_label.config(text=current_time)  # 更新标签文本
    root.after(1000, update_time)  # 每隔1秒更新一次

# 创建时间标签，并将其放置在网格的最后一行，靠左对齐
time_label = tk.Label(root, text="", font=('Arial', 13, 'bold'), anchor="w")  # anchor="w"表示靠左对齐
time_label.grid(row=0, column=0, padx=20, pady=1, sticky="nw")

top_right_label = tk.Label(root, text=f"WIPRACK", font=('Arial', 13, 'bold'), anchor="e")
top_right_label.grid(row=0, column=4, padx=1, pady=1, sticky="ne")

# 创建底部中间的标签
bottom_center_label = tk.Label(root, text="Center Label", font=('Arial', 15, 'bold'), anchor="center")
bottom_center_label.grid(row=7, column=1, columnspan=3, padx=20, pady=20, sticky="ew")  # 跨3列，居中显示

CONNECTING_bottom_left_label = tk.Label(root, text="CONNECTING", font=('Arial', 15, 'bold'), anchor="w")
CONNECTING_bottom_left_label.grid(row=7, column=0, padx=20, pady=20, sticky="w")  # 靠左对齐

# 创建右下角的标签
CONNECTING_bottom_right_label = tk.Label(root, text="CONNECTING", font=('Arial', 15, 'bold'), anchor="e")
CONNECTING_bottom_right_label.grid(row=7, column=4, padx=20, pady=20, sticky="e")  # 靠右对齐

update_time()  # 调用函数开始更新时间
# Manually adjusting label positions
# Adjusting grid positions for labels in rows and columns
# Example: labels[0][0] to labels[1][14]
labels[0][0].grid(row=0, column=0)
labels[0][1].grid(row=1, column=0)
labels[0][2].grid(row=0, column=1)
labels[0][3].grid(row=1, column=1)
labels[0][4].grid(row=0, column=2)
labels[0][5].grid(row=1, column=2)
labels[0][6].grid(row=0, column=3)
labels[0][7].grid(row=1, column=3)
labels[0][8].grid(row=0, column=4)
labels[0][9].grid(row=1, column=4)
labels[0][10].grid(row=2, column=0)
labels[0][11].grid(row=3, column=0)
labels[0][12].grid(row=2, column=1)
labels[0][13].grid(row=3, column=1)
labels[0][14].grid(row=2, column=2)
labels[1][0].grid(row=3, column=2)
labels[1][1].grid(row=2, column=3)
labels[1][2].grid(row=3, column=3)
labels[1][3].grid(row=2, column=4)
labels[1][4].grid(row=3, column=4)
labels[1][5].grid(row=4, column=0)
labels[1][6].grid(row=5, column=0)
labels[1][7].grid(row=4, column=1)
labels[1][8].grid(row=5, column=1)
labels[1][9].grid(row=4, column=2)
labels[1][10].grid(row=5, column=2)
labels[1][11].grid(row=4, column=3)
labels[1][12].grid(row=5, column=3)
labels[1][13].grid(row=4, column=4)
labels[1][14].grid(row=5, column=4)
previous_data = None
previous_labels = labels
def update_labels():
    global USB_BUS, let_target_label_maintain_yellow , USB_DIS,data,labels,previous_data_cut,light_command_bytes,light_type,target,rgb_light_type,label_positions,previous_labels
    root.attributes("-fullscreen", True)
    '''Check USB Connection'''
    if not USB_BUS or not USB_BUS.is_open:
        USB_BUS = connect_USB_BUS() 
        if not USB_BUS:
            USB_DIS = 1
        else:
            USB_DIS = 0
    '''get usb data'''
    data[0] =  send_hex_command(USB_BUS, hex_command[0])   
    '''cut data in 30 piece'''
    split_length = 12  # 每段12個字元
    segments = []  # 用來存儲切分結果15                                                                                                                                                                                     
    light_type=0
    if data[0] :# 檢查 data[0] 是否為 None 或空字串
        for i in range(0, 360, split_length):
            segment = data[0][i:i + split_length]  # 從字串中提取12字元的切片
            segments.append(segment)  # 將切片加入到segments列表中

    # 把前15段放入 data_cut[0]，後15段放入 data_cut[1]
        data_cut = [segments[:15], segments[15:]]
        light_type=1
    else:
        #print("data[0] 是 None 或空字串，無法切分")
        data_cut = [[ None for _ in range(15)], [ None for _ in range(15)]] # 設置為空的二維列表

    '''Label Text And Color Condition'''
    if(USB_DIS==1):
        #with concurrent.futures.ThreadPoolExecutor(max_workers=5) as excutor:
            for i in range(2):
                for j in range(15):
                    grid_info = labels[i][j].grid_info()
                    row = grid_info['row']
                    column = grid_info['column']
                    labels[i][j].config(text='Device Disconnected', bg='red')
                    CASSETTEID ={'CASSETIED':labels[i][j]['text'],'CURR_DEV':f"WIPRACK{wiprack_data[0]}",'CURR_LOC': f"{row}_{column}",'LO_STATE':'5'}
                    #excutor.submit(send_message_wip_transfer, args=(CASSETTEID,))
                    let_target_label_maintain_yellow [i][j] = 'NO_Target'
    else:
        #time.sleep(0.15)
        wiprack_data[0] = send_wiprack_hex_command(USB_BUS, wiprack_hex_command[0])
        if wiprack_data[0] == None:
            top_right_label['text'] = f"WIPRACK{wiprack_data[0]}"
        else:
            top_right_label['text'] = f"WIPRACK{wiprack_data[0]+1}"
        est = time.time()
        for i in range(2):
            for j in range(15):
                if data_cut[i][j] == b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' or data_cut[i][j] == None  or  validate_string(data_cut[i][j])==False:
                    let_target_label_maintain_yellow [i][j] = 'NO_Target'
                    rgb_light_type = 3
                    labels[i][j].config(text='Empty', bg='green')
                    if light_type != 2:
                        light_type=1
                        RGB_LIGHT(rgb_light_type,i,j)
                elif let_target_label_maintain_yellow [i][j] == labels[i][j]['text'] :
                    rgb_light_type =2
                    labels[i][j].config(bg='yellow')
                    light_type=2
                    RGB_LIGHT(rgb_light_type,i,j)
                else:
                    ascii_resp = hex_to_ascii(data_cut[i][j].hex())
                    labels[i][j].config(text=ascii_resp, bg='gray')
                    rgb_light_type =1
                    if light_type != 2:
                        light_type=1
                        RGB_LIGHT(rgb_light_type,i,j)
        #print(time.time() - est)
    if light_type == 1:
        light_command_bytes = bytes.fromhex(light_hex_command[1])
    elif light_type == 2:
        light_command_bytes = bytes.fromhex(light_hex_command[2])
    else:
        light_command_bytes = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    #else:
        #light_command_bytes = bytes.fromhex(light_hex_command[0])
    if USB_BUS and USB_BUS.is_open:
        try:
            USB_BUS.write(light_command_bytes)
            bottom_center_label['text'] = "下位機連接成功"
        except serial.SerialException as e:
            print(f"串口通信错误: {e}")
            USB_BUS.close()
    else:
        #print("USB 端口未打开或连接失败")
        bottom_center_label['text'] = "下位機連接失敗"
       
    #Label And Target Compartion Condition
    for i in range(2):
        for j in range(15):
            if target == labels[i][j]['text']:
                #labels[i][j].config(bg='yellow')
                let_target_label_maintain_yellow [i][j] = labels[i][j]['text']
                target = None
    ###如果tag出現變化執行
    for num_1 in range(2):
        for num_2 in range(15):
            bg_color = labels[num_1][num_2].cget('bg')
            prebg_color= previous_labels[num_1][num_2].cget('bg')
            if data_cut[num_1][num_2]!=previous_data_cut[num_1][num_2] or  bg_color != prebg_color :
                row, column = label_positions[(num_1, num_2)]
                if bg_color == 'gray':
                    loc_state = '1'
                elif bg_color == 'yellow':
                    loc_state = '1'
                elif bg_color == 'green':
                    loc_state = '0'
                else:
                    continue  # 忽略不符合條件的顏色

            # 構建 CASSETTEID 字典
                CASSETTEID = {
                    'CASSETTEID': labels[num_1][num_2]['text'],
                    'CURR_DEV': f"WIPRACK{wiprack_data[0]}",
                    'CURR_LOC': f"{row}_{column}",
                    'LOC_STATE': loc_state
                }

            # 創建並啟動執行緒
                thread = threading.Thread(target=send_message_wip_transfer, args=(CASSETTEID,))
                thread.daemon = True
                thread.start()  # 開始執行緒
    previous_data_cut = data_cut               
    root.after(200, update_labels)
if __name__ == '__main__':
    # Server configuration
    server_thread = threading.Thread(target=start_server)
    server_thread.daemon = False  # 设置为守护线程，主程序结束时自动结束
    server_thread.start()
    USB_BUS = connect_USB_BUS()
    '''update labels'''
    update_labels()
    root.attributes("-fullscreen", True)
    root.config(cursor="none")
    Searching_Event.bind('<Return>', event_label)
    root.mainloop()




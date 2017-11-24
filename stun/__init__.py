import binascii
import logging
import random
import socket

try:
    dict.iteritems
except AttributeError:
    # Python 3
    def listitems(d):
        return list(d.items())
else:
    # Python 2
    def listitems(d):
        return d.items()

__version__ = '0.1.0'

log = logging.getLogger("pystun")

STUN_SERVERS = (
    'stun.ekiga.net',
    'stun.ideasip.com',
    'stun.voiparound.com',
    'stun.voipbuster.com',
    'stun.voipstunt.com',
    'stun.voxgratia.org'
)

stun_servers_list = STUN_SERVERS

DEFAULTS = {
    'stun_port': 3478,
    'source_ip': '0.0.0.0',
    'source_port': 54320
}

# stun attributes
MappedAddress = '0001'
ResponseAddress = '0002'
ChangeRequest = '0003'
SourceAddress = '0004'
ChangedAddress = '0005'
Username = '0006'
Password = '0007'
MessageIntegrity = '0008'
ErrorCode = '0009'
UnknownAttribute = '000A'
ReflectedFrom = '000B'
XorOnly = '0021'
XorMappedAddress = '8020'
ServerName = '8022'
SecondaryAddress = '8050'  # Non standard extension

# types for a stun message
BindRequestMsg = '0001'
BindResponseMsg = '0101'
BindErrorResponseMsg = '0111'
SharedSecretRequestMsg = '0002'
SharedSecretResponseMsg = '0102'
SharedSecretErrorResponseMsg = '0112'

dictAttrToVal = {'MappedAddress': MappedAddress,
                 'ResponseAddress': ResponseAddress,
                 'ChangeRequest': ChangeRequest,
                 'SourceAddress': SourceAddress,
                 'ChangedAddress': ChangedAddress,
                 'Username': Username,
                 'Password': Password,
                 'MessageIntegrity': MessageIntegrity,
                 'ErrorCode': ErrorCode,
                 'UnknownAttribute': UnknownAttribute,
                 'ReflectedFrom': ReflectedFrom,
                 'XorOnly': XorOnly,
                 'XorMappedAddress': XorMappedAddress,
                 'ServerName': ServerName,
                 'SecondaryAddress': SecondaryAddress}

dictMsgTypeToVal = {
    'BindRequestMsg': BindRequestMsg,
    'BindResponseMsg': BindResponseMsg,
    'BindErrorResponseMsg': BindErrorResponseMsg,
    'SharedSecretRequestMsg': SharedSecretRequestMsg,
    'SharedSecretResponseMsg': SharedSecretResponseMsg,
    'SharedSecretErrorResponseMsg': SharedSecretErrorResponseMsg}

dictValToMsgType = {}

dictValToAttr = {}

Blocked = "Blocked"
OpenInternet = "Open Internet"
FullCone = "Full Cone"
SymmetricUDPFirewall = "Symmetric UDP Firewall"
RestricNAT = "Restric NAT"
RestricPortNAT = "Restric Port NAT"
SymmetricNAT = "Symmetric NAT"
ChangedAddressError = "Meet an error, when do Test1 on Changed IP and Port"


def _initialize():
    items = listitems(dictAttrToVal)
    for i in range(len(items)):
        dictValToAttr.update({items[i][1]: items[i][0]})
    items = listitems(dictMsgTypeToVal)
    for i in range(len(items)):
        dictValToMsgType.update({items[i][1]: items[i][0]})


def gen_tran_id():
    a = ''.join(random.choice('0123456789ABCDEF') for i in range(32))
    # return binascii.a2b_hex(a)
    return a


def stun_test(sock, host, port, source_ip, source_port, send_data=""):
    # 设置期望的返回数据结构
    retVal = {'Resp': False, 'ExternalIP': None, 'ExternalPort': None,
              'SourceIP': None, 'SourcePort': None, 'ChangedIP': None,
              'ChangedPort': None}
    # 构造要发送的数据
    # "%#04x" % 17 = 0x11 && "%04x" % 17 = 0011
    # "%#04d" 看上去和 "%04d" 没什么不同
    # 消息长度
    str_len = "%#04d" % (len(send_data) / 2)
    # 生成事务 ID
    tranid = gen_tran_id()
    # 生成要发出的数据 str_data
    # BindRequestMsg 0001 => 绑定消息类型
    # str_len 0000 => 消息长度
    # tranid 32位 => 事务 ID
    # send_data '' => 要发出的数据(空字符串)
    str_data = ''.join([BindRequestMsg, str_len, tranid, send_data])
    # binascii => Conversion between binary data and ASCII
    data = binascii.a2b_hex(str_data)
    # 标志返回消息是否正确
    recvCorr = False
    while not recvCorr:
        recieved = False
        # UDP 数据包重发 3 次
        count = 3
        while not recieved:
            log.debug("sendto: %s", (host, port))
            try:
                sock.sendto(data, (host, port))
            except socket.gaierror:
                retVal['Resp'] = False
                return retVal
            try:
                # 返回数据读取至 buf
                buf, addr = sock.recvfrom(2048)
                log.debug("recvfrom: %s", addr)
                recieved = True
            except Exception:
                recieved = False
                if count > 0:
                    count -= 1
                else:
                    retVal['Resp'] = False
                    return retVal
        # 解析返回消息的类型原始数据
        msgtype = binascii.b2a_hex(buf[0:2]).decode('utf-8')
        # 判断消息类型等于 BindResponseMsg
        bind_resp_msg = dictValToMsgType[msgtype] == "BindResponseMsg"
        # 判断事务 ID 匹配
        tranid_match = tranid.upper() == binascii.b2a_hex(buf[4:20]).upper().decode('utf-8')
        if bind_resp_msg and tranid_match:
            recvCorr = True
            retVal['Resp'] = True
            # 解析消息长度
            len_message = int(binascii.b2a_hex(buf[2:4]), 16)
            len_remain = len_message
            base = 20
            # 解析所有返回值到 retVal
            # 直到 len_remain == 0
            while len_remain:
                attr_type = binascii.b2a_hex(buf[base:(base + 2)]).decode('utf-8')
                attr_len = int(binascii.b2a_hex(buf[(base + 2):(base + 4)]), 16)
                if attr_type == MappedAddress:
                    port = int(binascii.b2a_hex(buf[base + 6:base + 8]), 16)
                    ip = ".".join([
                        str(int(binascii.b2a_hex(buf[base + 8:base + 9]), 16)),
                        str(int(binascii.b2a_hex(buf[base + 9:base + 10]), 16)),
                        str(int(binascii.b2a_hex(buf[base + 10:base + 11]), 16)),
                        str(int(binascii.b2a_hex(buf[base + 11:base + 12]), 16))
                    ])
                    retVal['ExternalIP'] = ip
                    retVal['ExternalPort'] = port
                if attr_type == SourceAddress:
                    port = int(binascii.b2a_hex(buf[base + 6:base + 8]), 16)
                    ip = ".".join([
                        str(int(binascii.b2a_hex(buf[base + 8:base + 9]), 16)),
                        str(int(binascii.b2a_hex(buf[base + 9:base + 10]), 16)),
                        str(int(binascii.b2a_hex(buf[base + 10:base + 11]), 16)),
                        str(int(binascii.b2a_hex(buf[base + 11:base + 12]), 16))
                    ])
                    retVal['SourceIP'] = ip
                    retVal['SourcePort'] = port
                if attr_type == ChangedAddress:
                    port = int(binascii.b2a_hex(buf[base + 6:base + 8]), 16)
                    ip = ".".join([
                        str(int(binascii.b2a_hex(buf[base + 8:base + 9]), 16)),
                        str(int(binascii.b2a_hex(buf[base + 9:base + 10]), 16)),
                        str(int(binascii.b2a_hex(buf[base + 10:base + 11]), 16)),
                        str(int(binascii.b2a_hex(buf[base + 11:base + 12]), 16))
                    ])
                    retVal['ChangedIP'] = ip
                    retVal['ChangedPort'] = port
                # if attr_type == ServerName:
                    # serverName = buf[(base+4):(base+4+attr_len)]
                base = base + 4 + attr_len
                len_remain = len_remain - (4 + attr_len)
    # s.close()
    return retVal


def get_nat_type(s, source_ip, source_port, stun_host=None, stun_port=3478):
    """
    RFC3489 文档:
    客户首先从测试 I 开始。如果该测试没有响应，客户就知道他不能使用UDP连接。如果测试产生响应，则客户检查MAPPED-ADDRESS属性。
    如果其中的地址和端口与用来发送请求的套接口的本地IP地址和端口相同，则客户知道他没有通过NAT。然后执行测试II。

    如果收到响应，则客户知道他与互联网之间可互访（或者，至少，他在表现如同完全锥型NAT且没有进行转换的防火墙后）。
    如果没有响应，则客户知道他在对称型UDP防火墙之后。

    在套接口的 IP 地址和端口与测试 I 响应的 MAPPED-ADDRESS 属性中的不同的情况下，客户就知道他在 NAT 后。他执行测试 II。
    如果收到响应，则客户知道他在完全锥型NAT后。如果没有响应，他再次执行测试I，但这次，使测试I响应的 CHANGED-ADDRESS 属性中的地址和端口。
    如果MAPPED-ADDRESS中返回的IP地址和端口与第一次测试I中的不同，客户就知道他在对称型NAT后。如果地址和端口相同，则客户要么在限制 NAT 后，要么在端口限制NAT后。
    要判断出到底是哪种，客户进行测试 III。如果收到响应，则他在限制NAT后，如果没有响应，则他在端口限制 NAT 后。

    该过程产生关于客户应用程序的操作条件的实际信息。在客户与互联网间存在多级NAT的情况下，发现的类型将是客户与互联网间限制最多的NAT的类型。
    NAT的类型接照限制排序从高到低是对称型，端口限制锥型，限制锥型和完全锥型。
    """
    # 初始化 RFC3489/STUN 定义的数据结构，详情 https://tools.ietf.org/html/rfc3489
    _initialize()
    port = stun_port
    # 开始 测试-1
    log.debug("Do Test1")
    # 标志 stun_test() 返回是否成功
    resp = False
    if stun_host:
        ret = stun_test(s, stun_host, port, source_ip, source_port)
        resp = ret['Resp']
    else:
        for stun_host in stun_servers_list:
            log.debug('Trying STUN host: %s', stun_host)
            ret = stun_test(s, stun_host, port, source_ip, source_port)
            resp = ret['Resp']
            if resp:
                break
    if not resp:
        return Blocked, ret
    log.debug("Result: %s", ret)
    # 获取第一次测试的
    # ExternalIP
    # ExternalPort
    # ChangedIP
    # ChangedPort
    exIP = ret['ExternalIP']
    exPort = ret['ExternalPort']
    changedIP = ret['ChangedIP']
    changedPort = ret['ChangedPort']
    if ret['ExternalIP'] == source_ip:
        # 构建第二次测试的消息体
        changeRequest = ''.join([ChangeRequest, '0004', "00000006"])
        ret = stun_test(s, stun_host, port, source_ip, source_port,
                        changeRequest)
        if ret['Resp']:
            typ = OpenInternet
        else:
            typ = SymmetricUDPFirewall
    else:
        changeRequest = ''.join([ChangeRequest, '0004', "00000006"])
        log.debug("Do Test2")
        ret = stun_test(s, stun_host, port, source_ip, source_port,
                        changeRequest)
        log.debug("Result: %s", ret)
        if ret['Resp']:
            typ = FullCone
        else:
            log.debug("Do Test1")
            ret = stun_test(s, changedIP, changedPort, source_ip, source_port)
            log.debug("Result: %s", ret)
            if not ret['Resp']:
                typ = ChangedAddressError
            else:
                if exIP == ret['ExternalIP'] and exPort == ret['ExternalPort']:
                    changePortRequest = ''.join([ChangeRequest, '0004',
                                                 "00000002"])
                    log.debug("Do Test3")
                    ret = stun_test(s, changedIP, port, source_ip, source_port,
                                    changePortRequest)
                    log.debug("Result: %s", ret)
                    if ret['Resp']:
                        typ = RestricNAT
                    else:
                        typ = RestricPortNAT
                else:
                    typ = SymmetricNAT
    return typ, ret


def get_ip_info(source_ip="0.0.0.0", source_port=54320, stun_host=None,
                stun_port=3478):
    # 创建一个 IPv4 协议的 UDP socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Set a timeout on blocking socket operations.
    s.settimeout(2)
    # 设置额外的 socket 行为：关闭 socket 之后想继续重用该 socket
    # setsockopt 设置 socket 详细用法(http://blog.chinaunix.net/uid-25324849-id-207869.html)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Bind the socket to address.
    s.bind((source_ip, source_port))
    # 通过 stun 服务器获取 nat_type 和 nat 设备信息
    nat_type, nat = get_nat_type(s, source_ip, source_port,
                                 stun_host=stun_host, stun_port=stun_port)
    external_ip = nat['ExternalIP']
    external_port = nat['ExternalPort']
    s.close()
    return (nat_type, external_ip, external_port)

import netfilterqueue
from scapy.all import *
from scapy.layers.inet import TCP, IP
import hashlib
import socket
import pickle
from tinyec import registry
from Crypto.Cipher import AES
import secrets
from simon_cipher import SimonCipher

PORT = 2333
curve = None
privKey = None
pubKey = None
curve_bytes = None
pubKey_bytes = None
KEY = None
global cipher
cipher = SimonCipher()
ready_to_encrypt_header=0

wait_to_send_ack=[]



def encrypt_AES_GCM(msg, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM)
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
    return (ciphertext, aesCipher.nonce, authTag)


def decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
    return plaintext


def ecc_point_to_256_bit_key(point):
    sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
    sha.update(int.to_bytes(point.y, 32, 'big'))
    return sha.digest()


curve = registry.get_curve('brainpoolP256r1')


def encrypt_ECC(msg, pubKey):
    ciphertextPrivKey = secrets.randbelow(curve.field.n)
    sharedECCKey = ciphertextPrivKey * pubKey
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    ciphertext, nonce, authTag = encrypt_AES_GCM(msg, secretKey)
    ciphertextPubKey = ciphertextPrivKey * curve.g
    return (ciphertext, nonce, authTag, ciphertextPubKey)


def decrypt_ECC(encryptedMsg, privKey):
    (ciphertext, nonce, authTag, ciphertextPubKey) = encryptedMsg
    sharedECCKey = privKey * ciphertextPubKey
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    plaintext = decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey)
    return plaintext


def process(packet):
    global encryptedMsg_bytes
    global curve
    global KEY
    global cipher
    global ready_to_encrypt_header
    pkt = IP(packet.get_payload())
    if pkt.haslayer(TCP) and pkt[TCP].dport == PORT:
        print("------------------------------------")
        print("-----------------Sending-------------------")
        print("Flag:", pkt[TCP].flags)
        print("Seq:", pkt[TCP].seq)
        print("Ack:", pkt[TCP].ack)

        #ready_to_encrypt_header
        if KEY != None and ready_to_encrypt_header==1:
            cipher.key = KEY
            # pkt[TCP].show()
            or_seq = pkt[TCP].seq
            print(f"Origin seq: {or_seq}")
            or_ack = pkt[TCP].ack
            print(f"Origin ack: {or_ack}")

            or_seq = (or_seq >> SimonCipher.WORD_SIZE, or_seq & ((1 << SimonCipher.WORD_SIZE) - 1))
            en_seq = cipher.encrypt(or_seq)
            en_seq_int = (en_seq[0] << 16) | en_seq[1]
            pkt[TCP].seq = en_seq_int
            print(f"Encrypted seq: {en_seq_int}")

            or_ack = (or_ack >> SimonCipher.WORD_SIZE, or_ack & ((1 << SimonCipher.WORD_SIZE) - 1))
            en_ack = cipher.encrypt(or_ack)
            en_ack_int = (en_ack[0] << 16) | en_ack[1]
            pkt[TCP].ack = en_ack_int
            print(f"Encrypted ack: {en_ack_int}")

            # Reset checksum
            del pkt[TCP].chksum
            del pkt[IP].len
            del pkt[IP].chksum
            pkt = pkt.__class__(bytes(pkt))
            pkt[TCP] = pkt[TCP].__class__(bytes(pkt[TCP]))
            packet.set_payload(bytes(pkt))
            packet.accept()
            return

        # set ECC things
        if pkt[TCP].flags ==  0x002:
            print("TCP SYN packet detected, setting TCP Fast Open...")
            # print(pkt[TCP].options)
            # oplist=pkt[TCP].options
            # oplist.append(("TFO", (0, 0)))
            # pkt[TCP].options = oplist
            #
            # options_length = sum(len(option) if isinstance(option, tuple) else 1 for option in pkt[TCP].options)
            # # 计算填充字节的数量，以使选项与 4 字节边界对齐
            # padding_length = (4 - (options_length % 4)) % 4
            # # 添加填充字节（NOP 选项）
            # pkt[TCP].options.extend([(1,)] * padding_length)
            # # 更新 Data Offset 字段，以反映新的 TCP 头部长度
            # pkt[TCP].dataofs = (pkt[TCP].dataofs * 4 + options_length + padding_length) // 4
            #
            # print(pkt[TCP].options)
            # #pkt[TCP].payload = Raw(load=b"Hello, Server!")
            # del pkt[TCP].chksum
            # del pkt[IP].len
            # del pkt[IP].chksum
            # packet.set_payload(bytes(pkt))

        if pkt[TCP].flags== 0x010 :
            print(pkt[TCP].payload)
            if pkt[TCP].seq in wait_to_send_ack :
                wait_to_send_ack.remove(pkt[TCP].seq)
                print("TCP handshake completed Ack")
                pkt[TCP].payload = Raw(load=b'ECC1#&!' + encryptedMsg_bytes + b'#&!')
                print("Send ECC msg back within ack")
                #Reset checksum
                del pkt[TCP].chksum
                del pkt[IP].len
                del pkt[IP].chksum
                pkt = pkt.__class__(bytes(pkt))
                pkt[TCP] = pkt[TCP].__class__(bytes(pkt[TCP]))
                packet.set_payload(bytes(pkt))
                ready_to_encrypt_header = 1
        print("------------------------------------")
        packet.accept()
    elif pkt.haslayer(TCP) and pkt[TCP].sport == PORT:
        print("------------------------------------")
        print("----------------Receiving---------------")
        print("Flag:", pkt[TCP].flags)
        print("Seq:", pkt[TCP].seq)
        print("Ack:", pkt[TCP].ack)
        # ready_to_encrypt_header
        if KEY != None and ready_to_encrypt_header == 1:
            cipher.key = KEY
            # pkt[TCP].show()
            en_seq_int = pkt[TCP].seq
            print(f"Encrypted seq: {en_seq_int}")
            en_ack_int = pkt[TCP].ack
            print(f"Encrypted ack: {en_ack_int}")

            en_seq = (en_seq_int >> SimonCipher.WORD_SIZE, en_seq_int & ((1 << SimonCipher.WORD_SIZE) - 1))
            or_seq = cipher.decrypt(en_seq)
            or_seq_int = (or_seq[0] << 16) | or_seq[1]
            pkt[TCP].seq = or_seq_int
            print(f"Origin seq: {or_seq_int}")

            en_ack = (en_ack_int >> SimonCipher.WORD_SIZE, en_ack_int & ((1 << SimonCipher.WORD_SIZE) - 1))
            or_ack = cipher.decrypt(en_ack)
            or_ack_int = (or_ack[0] << 16) | or_ack[1]
            pkt[TCP].ack = or_ack_int
            print(f"Origin ack: {or_ack_int}")

            # Reset checksum
            del pkt[TCP].chksum
            del pkt[IP].len
            del pkt[IP].chksum
            pkt = pkt.__class__(bytes(pkt))
            pkt[TCP] = pkt[TCP].__class__(bytes(pkt[TCP]))
            packet.set_payload(bytes(pkt))
            packet.accept()
            return


        # set ECC things
        if pkt[TCP].flags== 0x012 :
            print("TCP handshake SYN+ACK")
            data = bytes(pkt[TCP].payload)
            if data.find(b"ECC#&!") != -1:
                print("Detected ECC:", pkt[TCP].payload)
                wait_to_send_ack.append(pkt[TCP].ack)
                listd = data.split(b"#&!")
                print("cut list", len(listd))
                if listd[0] == b'ECC' and len(listd)==4:
                    print("Receive a valid ECC")
                    curve_bytes = listd[1]
                    pubKey_bytes = listd[2]
                    # print(pubKey_bytes)

                    curve = pickle.loads(curve_bytes)
                    pubKey = pickle.loads(pubKey_bytes)
                    #msg = input("请输入要加密发送的消息：")
                    cipher = SimonCipher()
                    KEY = cipher.key
                    print(f"Generated key: {KEY}")
                    print("KEY set")
                    #msg = bytes(cipher.key)
                    key_bytes = cipher.key.to_bytes(8, 'big')
                    encryptedMsg = encrypt_ECC(key_bytes, pubKey)
                    # encryptedMsgObj = {
                    #     'ciphertext': binascii.hexlify(encryptedMsg[0]),
                    #     'nonce': binascii.hexlify(encryptedMsg[1]),
                    #     'authTag': binascii.hexlify(encryptedMsg[2]),
                    #     'ciphertextPubKey': hex(encryptedMsg[3].x) + hex(encryptedMsg[3].y % 2)[2:]
                    # }
                    # print("encrypted msg:", encryptedMsgObj)

                    encryptedMsg_bytes = pickle.dumps(encryptedMsg)
        print("------------------------------------")
        packet.accept()

    else:
        # Other things
        packet.accept()


# OLD AND WORKS
# def process(packet):
#     pkt = IP(packet.get_payload())
#     if pkt.haslayer(TCP) and pkt[TCP].dport == PORT:
#         print("------------------------------------")
#         print("-----------------Sending-------------------")
#         global KEY
#         global lastone
#         global allready
#         if KEY != None and allready==1:
#
#             cipher.key = KEY
#             # pkt[TCP].show()
#             or_seq = pkt[TCP].seq
#             print(f"Origin ack: {or_seq}")
#             or_ack = pkt[TCP].ack
#             print(f"Origin ack: {or_ack}")
#
#             or_seq = (or_seq >> SimonCipher.WORD_SIZE, or_seq & ((1 << SimonCipher.WORD_SIZE) - 1))
#             en_seq = cipher.encrypt(or_seq)
#             en_seq_int = (en_seq[0] << 16) | en_seq[1]
#             pkt[TCP].seq = en_seq_int
#             print(f"Encrypted seq: {en_seq_int}")
#
#             or_ack = (or_ack >> SimonCipher.WORD_SIZE, or_ack & ((1 << SimonCipher.WORD_SIZE) - 1))
#             en_ack = cipher.encrypt(or_ack)
#             en_ack_int = (en_ack[0] << 16) | en_ack[1]
#             pkt[TCP].ack = en_ack_int
#             print(f"Encrypted ack: {en_ack_int}")
#
#             # Reset checksum
#             del pkt[TCP].chksum
#             del pkt[IP].len
#             del pkt[IP].chksum
#             pkt = pkt.__class__(bytes(pkt))
#             pkt[TCP] = pkt[TCP].__class__(bytes(pkt[TCP]))
#             packet.set_payload(bytes(pkt))
#             packet.accept()
#             return
#         elif lastone==1:
#             lastone=lastone-1
#             allready=1
#         print("-------Before Change-------")
#         print(pkt[TCP].payload)
#         print("-------After Change-------")
#         # TEST
#         # pkt[TCP].seq = pkt[TCP].seq - 1
#         data = bytes(pkt[TCP].payload)
#         if data.find(b"#&!") != -1:
#             # raw = pkt[Raw]
#             # print(raw.load)
#             listd = data.split(b"#&!")
#             print("分割数", len(listd))
#             if listd[0] == b'ECC':
#                 print("Start ECC")
#                 curve = registry.get_curve('brainpoolP256r1')
#                 global privKey
#                 privKey = secrets.randbelow(curve.field.n)
#                 pubKey = privKey * curve.g
#                 curve_bytes = pickle.dumps(curve)
#                 pubKey_bytes = pickle.dumps(pubKey)
#                 loaddata = b"ECC#&!" + curve_bytes + b"#&!" + pubKey_bytes + b"#&!"
#                 print(len(loaddata))
#                 pkt.show2()
#                 # loaddata = b"122#&!"
#                 pkt[Raw].load = loaddata
#                 # Reset checksum
#                 del pkt[IP].len
#                 del pkt[TCP].chksum
#                 del pkt[IP].chksum
#                 pkt = pkt.__class__(bytes(pkt))
#                 pkt[TCP] = pkt[TCP].__class__(bytes(pkt[TCP]))
#                 pkt.show2()
#                 #print(pkt[TCP].payload)
#                 print("ECC+PARAM")
#                 # 将修改后的数据包重新发送回网络
#                 packet.set_payload(bytes(pkt))
#
#         print("------------------------------------")
#         packet.accept()
#     elif pkt.haslayer(TCP) and pkt[TCP].sport == PORT:
#         print("----------------Receiving---------------")
#         if KEY != None and allready==1:
#
#             cipher.key = KEY
#             # pkt[TCP].show()
#             en_seq_int = pkt[TCP].seq
#             print(f"Encrypted ack: {en_seq_int}")
#             en_ack_int = pkt[TCP].ack
#             print(f"Encrypted ack: {en_ack_int}")
#
#             en_seq = (en_seq_int >> SimonCipher.WORD_SIZE, en_seq_int & ((1 << SimonCipher.WORD_SIZE) - 1))
#             or_seq = cipher.decrypt(en_seq)
#             or_seq_int = (or_seq[0] << 16) | or_seq[1]
#             pkt[TCP].seq = or_seq_int
#             print(f"Origin seq: {or_seq_int}")
#
#             en_ack = (en_ack_int >> SimonCipher.WORD_SIZE, en_ack_int & ((1 << SimonCipher.WORD_SIZE) - 1))
#             or_ack = cipher.decrypt(en_ack)
#             or_ack_int = (or_ack[0] << 16) | or_ack[1]
#             pkt[TCP].ack = or_ack_int
#             print(f"Origin ack: {or_ack_int}")
#
#             # Reset checksum
#             del pkt[TCP].chksum
#             del pkt[IP].len
#             del pkt[IP].chksum
#             pkt = pkt.__class__(bytes(pkt))
#             pkt[TCP] = pkt[TCP].__class__(bytes(pkt[TCP]))
#             packet.set_payload(bytes(pkt))
#             packet.accept()
#             return
#         print("-------Before Change-------")
#         #print(pkt[TCP].payload)
#         print("-------After Change-------")
#         # TEST
#         # pkt[TCP].ack = pkt[TCP].ack-1
#         data = bytes(pkt[TCP].payload)
#         if data.find(b"#&!") != -1:
#             listd = data.split(b"#&!")
#             print("分割数", len(listd))
#             if listd[0] == b'ECC1':
#                 print("Finish ECC1")
#                 encryptedMsg_bytes = listd[1]
#                 encryptedMsg = pickle.loads(encryptedMsg_bytes)
#
#                 if KEY == None:
#                     decryptedMsg = decrypt_ECC(encryptedMsg, privKey)
#                     if decryptedMsg != None:
#                         KEY = int.from_bytes(decryptedMsg, 'big')
#                         print("KEY :", KEY)
#                         #lastone=1
#                         allready = 1
#                         loaddata = b"ECCFINISH#&!"
#                         pkt[Raw].load = loaddata
#                     else:
#                         loaddata = b"ECCFAIL#&!"
#                         pkt[Raw].load = loaddata
#
#                 # Reset checksum
#                 del pkt[TCP].chksum
#                 del pkt[IP].len
#                 del pkt[IP].chksum
#                 pkt = pkt.__class__(bytes(pkt))
#                 pkt[TCP] = pkt[TCP].__class__(bytes(pkt[TCP]))
#                 # pkt.show2()
#                 #print(pkt[TCP].payload)
#                 # 将修改后的数据包重新发送回网络
#                 packet.set_payload(bytes(pkt))
#
#         print("------------------------------------")
#         packet.accept()
#     else:
#         packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(2, process)
queue.run()

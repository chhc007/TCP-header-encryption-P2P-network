import netfilterqueue
from scapy.all import *
from scapy.layers.inet import TCP, IP
import pickle
import socket
from tinyec import registry
import secrets
import hashlib
from Crypto.Cipher import AES
from simon_cipher import SimonCipher
PORT=2333

# ECC服务器固定内容
privKey = None
curve = None
pubKey = None
encryptedMsg_bytes=None

cipher=None
cipher = SimonCipher()
KEY=None

ready_to_encrypt_header=0

SentSYNACK_list=[]

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
    global KEY
    global privKey
    global ready_to_encrypt_header
    global curve
    global cipher

    pkt = IP(packet.get_payload())
    if pkt.haslayer(TCP) and pkt[TCP].dport == PORT:
        print("------------------------------------")
        print("-----------------Receiving-------------------")
        print("Flag:", pkt[TCP].flags)
        print("Seq:", pkt[TCP].seq)
        print("Ack:", pkt[TCP].ack)
        data = bytes(pkt[TCP].payload)

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
        if data.find(b"ECC1#&!") != -1:
            listd = data.split(b"#&!")
            print("cut list", len(listd))
            if listd[0] == b'ECC1' and len(listd)==3:
                print("Finish ECC")
                encryptedMsg_bytes = listd[1]
                encryptedMsg = pickle.loads(encryptedMsg_bytes)
                if KEY == None:
                    decryptedMsg = decrypt_ECC(encryptedMsg, privKey)
                    if decryptedMsg != None:
                        KEY = int.from_bytes(decryptedMsg, 'big')
                        print("KEY :", KEY)
                        ready_to_encrypt_header=1
        # modify
        if pkt[TCP].flags == 0x002:
            print("TCP SYN packet detected")
            # if ("TFO", (0, 0)) in pkt[TCP].options:
            #     print("TCP Fast Open detected")
            #     #fastopen_pkg_seqs.append(pkt[TCP].seq)
            #     print(pkt[TCP].payload)
        if pkt[TCP].flags == 0x010:
            if pkt[TCP].seq in SentSYNACK_list:
                print("TCP handshake over ACK packet detected")
                SentSYNACK_list.remove(pkt[TCP].seq)
                pkt[TCP].payload = Raw(load=b"")
                #pkt[TCP].flags=0x010
                del pkt[TCP].chksum
                del pkt[IP].len
                del pkt[IP].chksum
                pkt = pkt.__class__(bytes(pkt))
                pkt[TCP] = pkt[TCP].__class__(bytes(pkt[TCP]))
                packet.set_payload(bytes(pkt))

        print("------------------------------------")
        packet.accept()
    elif pkt.haslayer(TCP) and pkt[TCP].sport == PORT:
        print("------------------------------------")
        print("----------------Sending---------------")
        print("Flag:", pkt[TCP].flags)
        print("Seq:", pkt[TCP].seq)
        print("Ack:", pkt[TCP].ack)

        #ready_to_encrypt_header
        if KEY != None and ready_to_encrypt_header == 1:
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
        if pkt[TCP].flags == 0x012:
            print("TCP SYN-ACK packet detected add something")

            print("Start ECC")
            curve = registry.get_curve('brainpoolP256r1')

            privKey = secrets.randbelow(curve.field.n)
            pubKey = privKey * curve.g
            curve_bytes = pickle.dumps(curve)
            pubKey_bytes = pickle.dumps(pubKey)
            pkt[TCP].payload = Raw(load=b"ECC#&!" + curve_bytes + b"#&!" + pubKey_bytes + b"#&!")
            SentSYNACK_list.append(pkt[TCP].ack)
            #pkt[TCP].ack += len(b"HelloECC")

            del pkt[TCP].chksum
            del pkt[IP].len
            del pkt[IP].chksum
            packet.set_payload(bytes(pkt))

            # else:
            #     packet.accept()
            #     return

        print("------------------------------------")
        packet.accept()
    else:
        # Other things
        packet.accept()

#old and works
# def process(packet):
#     pkt = IP(packet.get_payload())
#     if pkt.haslayer(TCP) and pkt[TCP].dport == PORT:
#         print("------------------------------------")
#         print("-----------------Receiving-------------------")
#         global KEY
#         global allready
#         global lastone
#         if KEY != None and allready==1:
#             global cipher
#             cipher.key = KEY
#             # pkt[TCP].show()
#             if pkt[TCP].flags==0x010 :
#                 print("It's a ACK")
#             en_seq_int = pkt[TCP].seq
#             print(f"Encrypted seq: {en_seq_int}")
#             en_ack_int = pkt[TCP].ack
#             print(f"Encrypted ack: {en_ack_int}")
#
#             en_seq = (en_seq_int >> SimonCipher.WORD_SIZE, en_seq_int & ((1 << SimonCipher.WORD_SIZE) - 1))
#             or_seq=cipher.decrypt(en_seq)
#             or_seq_int=(or_seq[0] << 16) | or_seq[1]
#             pkt[TCP].seq = or_seq_int
#             print(f"Origin seq: {or_seq_int}")
#
#             en_ack = (en_ack_int >> SimonCipher.WORD_SIZE, en_ack_int & ((1 << SimonCipher.WORD_SIZE) - 1))
#             or_ack=cipher.decrypt(en_ack)
#             or_ack_int=(or_ack[0] << 16) | or_ack[1]
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
#         print(pkt[TCP].payload)
#         #pkt.show2()
#         print("-------After Change-------")
#         # TEST
#         #pkt[TCP].seq = pkt[TCP].seq - 10
#         data= bytes(pkt[TCP].payload)
#         if data.find(b"#&!") != -1:
#             listd = data.split(b"#&!")
#             print("分割数", len(listd))
#             if listd[0] == b'ECC':
#                 print("Receive ECC")
#                 curve_bytes = listd[1]
#                 pubKey_bytes = listd[2]
#                 # print(pubKey_bytes)
#                 global curve
#                 curve = pickle.loads(curve_bytes)
#                 pubKey = pickle.loads(pubKey_bytes)
#                 #msg = input("请输入要加密发送的消息：")
#                 cipher = SimonCipher()
#                 KEY = cipher.key
#                 print(f"Generated key: {KEY}")
#                 print("KEY set")
#
#                 #msg = bytes(cipher.key)
#                 key_bytes = cipher.key.to_bytes(8, 'big')
#                 encryptedMsg = encrypt_ECC(key_bytes, pubKey)
#                 # encryptedMsgObj = {
#                 #     'ciphertext': binascii.hexlify(encryptedMsg[0]),
#                 #     'nonce': binascii.hexlify(encryptedMsg[1]),
#                 #     'authTag': binascii.hexlify(encryptedMsg[2]),
#                 #     'ciphertextPubKey': hex(encryptedMsg[3].x) + hex(encryptedMsg[3].y % 2)[2:]
#                 # }
#                 # print("encrypted msg:", encryptedMsgObj)
#                 global encryptedMsg_bytes
#                 encryptedMsg_bytes = pickle.dumps(encryptedMsg)
#
#                 loaddata = b'ECCDONE#&!'
#                 pkt[Raw].load = loaddata
#
#                 # Reset checksum
#                 del pkt[TCP].chksum
#                 del pkt[IP].len
#                 del pkt[IP].chksum
#                 pkt = pkt.__class__(bytes(pkt))
#                 pkt[TCP] = pkt[TCP].__class__(bytes(pkt[TCP]))
#                 #pkt.show2()
#                 packet.set_payload(bytes(pkt))
#
#         print("------------------------------------")
#         packet.accept()
#
#     elif pkt.haslayer(TCP) and pkt[TCP].sport == PORT:
#         print("----------------Sending---------------")
#         if KEY != None and allready==1:
#             cipher.key = KEY
#             # pkt[TCP].show()
#             or_seq = pkt[TCP].seq
#             print(f"Origin seq: {or_seq}")
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
#             print(f"Encrypted ack: {en_ack_int }")
#             # Reset checksum
#             del pkt[TCP].chksum
#             del pkt[IP].len
#             del pkt[IP].chksum
#             pkt = pkt.__class__(bytes(pkt))
#             pkt[TCP] = pkt[TCP].__class__(bytes(pkt[TCP]))
#             packet.set_payload(bytes(pkt))
#             packet.accept()
#             return
#
#         print("-------Before Change-------")
#         #print(pkt[TCP].ack)
#         print(pkt[TCP].payload)
#         print("-------After Change-------")
#         # TEST
#         #pkt[TCP].ack = pkt[TCP].ack + 1
#         data = bytes(pkt[TCP].payload)
#         if data.find(b"#&!") != -1:
#             listd = data.split(b"#&!")
#             print("分割数", len(listd))
#             if listd[0] == b'ECC1':
#                 print("Start ECC1")
#                 loaddata=b'ECC1#&!' + encryptedMsg_bytes + b'#&!'
#                 print(len(loaddata))
#                 pkt[Raw].load = loaddata
#                 # Reset checksum
#                 del pkt[TCP].chksum
#                 del pkt[IP].len
#                 del pkt[IP].chksum
#                 pkt = pkt.__class__(bytes(pkt))
#                 pkt[TCP] = pkt[TCP].__class__(bytes(pkt[TCP]))
#                 #pkt.show2()
#                 # 将修改后的数据包重新发送回网络
#                 packet.set_payload(bytes(pkt))
#                 allready=1
#         print("------------------------------------")
#
#         packet.accept()
#     else:
#         packet.accept()


queue =netfilterqueue.NetfilterQueue()

queue.bind(2,process)
queue.run()

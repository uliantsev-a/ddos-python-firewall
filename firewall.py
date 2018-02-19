from scapy.all import *
import ifaddr

import time, os, datetime, threading
banned_ttl = []
banned_mss = []
banned_win = []
banned_seq = []

banned_ips = []

logf = open('logs/attacks.log', 'a')
bans = open('logs/bans.log', 'a')
ips_bans = open('bans/ips.ban', 'a')

dump = False
detecting = True
attack = False
dumping = True

lim = 2600
delay = 3
atl = 'attacks_logs'
ipt_flush = [
    "iptables -t raw -F" # not use
]

ipt_rules = [
    'iptables -t raw -A PREROUTING -p tcp --syn -m state --state NEW -j DROP',
    'iptables -t raw -A PREROUTING -p tcp --syn -m length --length 0 -j DROP',
    'iptables -t raw -A PREROUTING -p tcp --syn -m u32 --u32 "6&0xFF=0x6 && 0>>22&0x3C@12&0xFFFF=0x00:0x1fff" -j DROP'
]


ipt_block = {
    'ttl': '''iptables -t raw -I PREROUTING -p tcp --syn -m ttl --ttl-eq {0} -j DROP''',
    'win': '''iptables -t raw -I PREROUTING -p tcp --syn -m u32 --u32 "6&0xFF=0x6 && 0>>22&0x3C@12&0xFFFF={0}" -j DROP''',
    'mss': '''iptables -t raw -I PREROUTING -p tcp --syn -m tcpmss --mss {0} -j DROP'''
}

packets = {'wins': [], 'ttls': [], 'msss': [], 'seqs': [], 'dsts': []}


os.system("""/sbin/sysctl -w net/netfilter/nf_conntrack_tcp_loose=0
iptables -A INPUT -m state --state INVALID -j DROP
/sbin/sysctl -w net/ipv4/tcp_timestamps=1
echo 1000000 > /sys/module/nf_conntrack/parameters/hashsize
/sbin/sysctl -w net/netfilter/nf_conntrack_max=2000000
""")

proxy_drop_rules = ["iptables -t raw -I PREROUTING -i {0} -p tcp -m tcp --syn --dport {1} -j CT --notrack",
"iptables -A INPUT -i {0} -p tcp -m tcp --dport {1} -m state --state INVALID,UNTRACKED -j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460"
]

def get_adap_to_ip():
    dict_adap = {}
    adapters = ifaddr.get_adapters()
    for adap in adapters:
        for ip in adap.ips:
            dict_adap[ip.ip] = ip.nice_name.split(':')[0]
    return dict_adap

adap_dic = get_adap_to_ip()

def log(m):
    m = '[' + datetime.datetime.now().strftime("%d/%m/%y#%H:%M:%S") + '] ' + m
    if 'NO ATTACK,' not in m:
        logf.write(m + '\n')
    print(m)

def BAN(typ, c):
    if typ == 'win':
       os.system(ipt_block[typ].format(str(hex(c))))
    else:
        print(ipt_block[typ].format(c))
        os.system(ipt_block[typ].format(c))


def UNBAN():
    global banned_ttl, banned_seq, banned_win, banned_mss, banned_ips
    for i in ipt_flush: os.system(i)
    for i in ipt_rules: os.system(i)
    for i in banned_ips:
        os.system('iptables -A INPUT -s {} -j DROP'.format(i))
    banned_ttl, banned_win = [], []
    banned_seq, banned_mss = [], []
    log('[INFO] Standart rules loaded')

def DROP_PROXY(addr):
    adap = adap_dic.get(addr.ip)
    if adap:
        for cmd_proxy in proxy_drop_rules: 
            os.system(cmd_proxy.format(adap, addr.port))

    log('[INFO] DROP_PROXY {}:{}'.format(adap, addr.port))


def BLOCKER(TTLL, WINL, SEQL, MSSL, DSTL):
    global banned_ttl, banned_seq, banned_win, banned_mss

    if WINL:
        if WINL < 8096: TTLL = 0

    if TTLL:
        if TTLL > 101 and TTLL != 245:
            log('[FILTER] Banning TTL {}...\n'.format(TTLL))
            banned_ttl.append(TTLL)
            bans.write('{} banned by TTL\n'.format(TTLL))
            BAN('ttl', TTLL)
        else:
            log('[FILTER] TTL {} not banned...\n'.format(TTLL))
            bans.write('{} not ddos by TTL\n'.format(TTLL))

    if not TTLL or TTLL <= 101 or TTLL == 245:
        if WINL:
            log('[FILTER] Banning WIN {}...\n'.format(WINL))
            banned_win.append(WINL)
            bans.write('{} banned by WIN\n'.format(WINL))
            BAN('win', WINL)

        elif SEQL:
            log('[FILTER] Banning SEQ {}...\n'.format(SEQL))
            banned_seq.append(SEQL)
            bans.write('{} banned by SEQL\n'.format(SEQL))
            BAN('seq', SEQL)

        elif MSSL:
            if not MSSL == 1460:
                log('[FILTER] Banning MSS {}...\n'.format(MSSL))
                banned_mss.append(MSSL)
                bans.write('{} banned by MSS\n'.format(MSSL))
                BAN('mss', MSSL)
            else:
                log('[FILTER] Not banning MSS {}...\n'.format(MSSL))
                bans.write('{} not banned by MSS\n'.format(MSSL))

        elif DSTL:
            log('[FILTER] Banning DSTL {}...\n'.format(DSTL))
            bans.write('{} banned by DSTL\n'.format(DSTL))
            os.system('iptables -A INPUT -s {} -j DROP'.format(DSTL))


def ANALIZE_ATTACK():
    TTLL, WINL, SEQL, MSSL, DSTL = 0, 0, 0, 0, 0

    for w in packets['wins']:
        if packets['wins'].count(w) > 400:
            WINL = w

    for t in packets['ttls']:
        if packets['ttls'].count(t) > 400:
            TTLL = t

    for s in packets['seqs']:
        if packets['seqs'].count(s) > 400:
            SEQL = s

    for m in packets['msss']:
        if packets['msss'].count(m) > 400:
            MSSL = m

    for d in packets['dsts']:
        if packets['dsts'].count(d) > 400:
            DSTL = d

    if TTLL in banned_ttl: return
    if WINL in banned_win: return
    if SEQL in banned_seq: return
    if MSSL in banned_mss: return
    if dumping:
        threading.Thread(target=dump, args=(datetime.datetime.now().strftime("%d_%m_%y-%H_%M_%S"),)).start()
        print('Dumping started')
    log('[FILTER] -=-=-=-= Attacked: {} -=-=-=-='.format(DSTL))
    log('[FILTER] IPS: {}'.format(len(packets) - 4))
    if not WINL:
        log('[FILTER] Cant detect WIN Leader')
    else:
        log('[FILTER] Find WIN Leader:{}'.format(WINL))
    if not TTLL:
        log('[FILTER] Cant detect TTL Leader')
    else:
        log('[FILTER] Find TTL Leader: {}'.format(TTLL))
    if not SEQL:
        log('[FILTER] Cant detect SEQ Leader')
    else:
        log('[FILTER] Find SEQ Leader: {}'.format(SEQL))
    if not MSSL:
        log('[FILTER] Cant detect MSS Leader')
    else:
        log('[FILTER] Find MSS Leader: {}'.format(MSSL))
    if not WINL and not TTLL and not SEQL and not MSSL:
        log('[CRITICAL/FILTER] CANNOT MITIGATE ATTACK!\n')
    log('[FILTER] -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=')
    BLOCKER(TTLL, WINL, SEQL, MSSL, DSTL)

os.makedirs(atl, exist_ok=True)
os.makedirs('logs', exist_ok=True)
os.makedirs('bans', exist_ok=True)

def dump(name):
    command = os.popen('tcpdump -l -c 9000 -w {}/{}.pcap -n -i eno1 dst port 22 and inbound'.format(atl, name))
    return command

def console():
    global detecting, dumping
    while 1:
        try:
            command = input('> ').lower().split(' ')
            if command[0] == 'help':
                print('[HELP]  -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=')
                print(' > detect - Enable or disable auto attack detecting')
                print(' > dump   - Enable or disable auto dumping')
                print(' > help   - Show this window')
                print(' > junk [ban/clear] - Bans all win or clear all')
                print(' > ban IP - Ban ip by iptables')
                print('[HELP]  -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=')
            elif command[0] == 'junk':
                if command[1] == 'ban':
                    os.system('iptables -t raw -I PREROUTING -p tcp --syn -m u32 --u32 "6&0xFF=0x6 && 0>>22&0x3C@12&0xFFFF=1000" -j DROP')
                    log('[JUNK] Method was banned')
                elif command[1] == 'clear':
                    UNBAN()
                    log('[JUNK] Cleared!')
                else:
                    log('[JUNK] Pls type: [ban/clear]')
            elif command[0] == 'ban':
                if len(command) == 1:
                    banned_ips.append(command[1])
                    ips_bans.write(command[1] + '\n')
                    log('[BAN] {} successful banned'.format(command[1]))
            elif command[0] == 'dump':
                if dumping:
                    log('[FILTER] Auto dumping disabled')
                    dumping = False
                else:
                    log('[FILTER] Auto dumping enabled')
                    dumping = True
            elif command[0] == 'detect':
                if detecting:
                    log('[FILTER] Auto detecting disabled')
                    detecting = False
                else:
                    log('[FILTER] Auto detecting enabled')
                    detecting = True
            else:
                log('[FIREWALL] Unknown command!')
        except:
            log('[ERROR] command executes error')

threading.Thread(target=console).start()

with open('bans/ips.ban') as f:
    log('[LOAD] Many ips loaded')
    for line in f:
        banned_ips.append(f)

while 1:
    i = 0
    i_syn = 0
    i_ack = 0
    g_addr = None

    def start():
        global attack, packets, dumping
        if i > lim:
            if attack:
                log('[WARNING] STILL MITIGATING ATTACK -> %d all (%d SYN, %d ACK) packets per sec.' % (i, i_syn, i_ack))
            else:
                log('[WARNING] ATTACK DETECTED! -> %d all (%d SYN, %d ACK) packets per sec.\n' % (i, i_syn, i_ack))
            ANALIZE_ATTACK()
            time.sleep(delay)
            attack = True
        else:
            if attack:
                log('[WARNING] ATTACK MITIGATED, POWERING OFF FILTERS...\n')
                UNBAN()
                if g_addr:
                    DROP_PROXY(g_addr)
            packets = {'wins': [], 'ttls': [], 'msss': [], 'seqs': [], 'dsts': []}
            log('[INFO] NO ATTACK, {} all ({} SYN, {} ACK) packets per sec.'.format(i, i_syn, i_ack))
            attack = False
            time.sleep(1)


    def GET_print(packet1):
        global packets, i, i_ack, i_syn
        opts = 0
        SYN = 0x02
        ACK = 0x10
        i += 2
        try:
            IP = packet1['IP']
            TCP = packet1['TCP']
        except:
            return

        g_addr = {'ip': IP.dst, 'port': TCP.sport}
        # pdb.set_trace()
        if TCP.flags & SYN:
            i_syn += 2
        elif TCP.flags & ACK:
            i_ack += 2

        if len(TCP.options) > 0:
            if TCP.options[0][0] is 'MSS':
                opts = 1
        if IP.dport == 22: return
        packets[IP.src] = {}
        packets['wins'].append(TCP.window)
        packets['ttls'].append(IP.ttl)
        packets['seqs'].append(TCP.seq)
        packets['dsts'].append(IP.dst)
        if opts: packets['msss'].append(TCP.options[0][1])
        p = packets[IP.src]

        p['dst'] = IP.dst + ':%d' % IP.dport
        p['win'] = TCP.window
        p['ttl'] = IP.ttl
        p['seq'] = TCP.seq
        p['opts'] = TCP.options

    if detecting:
        sniff(prn=GET_print, filter="tcp[tcpflags] & (tcp-syn|tcp-ack) != 0", timeout=0.9, count=30000)
        start()
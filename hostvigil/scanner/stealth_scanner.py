"""
HostVigil Stealth Port Scanner

Enhanced port scanner with IDS evasion capabilities:
- Connect scan (default, no root needed) with stealth timing
- SYN half-open scan (requires root/admin) via scapy
- Protocol-specific service detection and banner grabbing
- Adaptive throttling based on RST rate (IDS evasion)
- Randomized scan order, per-host rate limiting
- Configurable decoy IPs, TTL manipulation, packet fragmentation
- Time-of-day scan window awareness
"""

import logging
import random
import socket
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

try:
    from scapy.all import IP, TCP, RandShort, conf, send, sr1

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

logger = logging.getLogger("hostvigil.scanner")

# ---------------------------------------------------------------------------
# Port Profiles
# ---------------------------------------------------------------------------

PORT_PROFILES = {
    "quick": [22, 80, 443, 445, 3389],
    "standard": [
        22,
        53,
        80,
        88,
        135,
        139,
        389,
        443,
        445,
        636,
        1433,
        3306,
        3389,
        5432,
        5985,
        5986,
        8080,
        8443,
        9200,
    ],
    "full": [
        21,
        22,
        23,
        25,
        53,
        80,
        88,
        110,
        111,
        135,
        139,
        143,
        389,
        443,
        445,
        465,
        514,
        587,
        636,
        993,
        995,
        1080,
        1433,
        1521,
        2049,
        2375,
        2376,
        3306,
        3389,
        5432,
        5900,
        5985,
        5986,
        6379,
        8080,
        8443,
        8888,
        9090,
        9200,
        9300,
        11211,
        27017,
    ],
    "top1000": [
        1,
        3,
        5,
        7,
        9,
        11,
        13,
        15,
        17,
        19,
        20,
        21,
        22,
        23,
        25,
        26,
        37,
        38,
        43,
        49,
        53,
        67,
        68,
        69,
        70,
        79,
        80,
        81,
        82,
        83,
        84,
        85,
        88,
        89,
        90,
        99,
        100,
        106,
        109,
        110,
        111,
        113,
        119,
        123,
        135,
        137,
        139,
        143,
        144,
        161,
        162,
        179,
        199,
        211,
        212,
        222,
        254,
        255,
        256,
        259,
        264,
        280,
        301,
        306,
        311,
        340,
        366,
        389,
        406,
        407,
        416,
        417,
        425,
        427,
        443,
        444,
        445,
        458,
        464,
        465,
        481,
        497,
        500,
        512,
        513,
        514,
        515,
        524,
        541,
        543,
        544,
        545,
        548,
        554,
        555,
        563,
        587,
        593,
        616,
        617,
        625,
        631,
        636,
        646,
        648,
        666,
        667,
        668,
        683,
        687,
        691,
        700,
        705,
        711,
        714,
        720,
        722,
        726,
        749,
        765,
        777,
        783,
        787,
        800,
        801,
        808,
        843,
        873,
        880,
        888,
        898,
        900,
        901,
        902,
        903,
        911,
        912,
        981,
        987,
        990,
        992,
        993,
        995,
        999,
        1000,
        1001,
        1002,
        1007,
        1009,
        1010,
        1011,
        1021,
        1022,
        1023,
        1024,
        1025,
        1026,
        1027,
        1028,
        1029,
        1030,
        1031,
        1032,
        1033,
        1034,
        1035,
        1036,
        1037,
        1038,
        1039,
        1040,
        1041,
        1042,
        1043,
        1044,
        1045,
        1046,
        1047,
        1048,
        1049,
        1050,
        1051,
        1052,
        1053,
        1054,
        1055,
        1056,
        1057,
        1058,
        1059,
        1060,
        1061,
        1062,
        1063,
        1064,
        1065,
        1066,
        1067,
        1068,
        1069,
        1070,
        1071,
        1072,
        1073,
        1074,
        1075,
        1076,
        1077,
        1078,
        1079,
        1080,
        1081,
        1082,
        1083,
        1084,
        1085,
        1086,
        1087,
        1088,
        1089,
        1090,
        1091,
        1092,
        1093,
        1094,
        1095,
        1096,
        1097,
        1098,
        1099,
        1100,
        1102,
        1104,
        1105,
        1106,
        1107,
        1108,
        1110,
        1111,
        1112,
        1113,
        1117,
        1119,
        1121,
        1122,
        1123,
        1124,
        1126,
        1130,
        1131,
        1132,
        1137,
        1138,
        1141,
        1145,
        1147,
        1148,
        1149,
        1151,
        1152,
        1154,
        1163,
        1164,
        1165,
        1166,
        1169,
        1174,
        1175,
        1183,
        1185,
        1186,
        1187,
        1192,
        1198,
        1199,
        1201,
        1213,
        1216,
        1217,
        1218,
        1233,
        1234,
        1236,
        1244,
        1247,
        1248,
        1259,
        1271,
        1272,
        1277,
        1287,
        1296,
        1300,
        1301,
        1309,
        1310,
        1311,
        1322,
        1328,
        1334,
        1352,
        1417,
        1433,
        1434,
        1443,
        1455,
        1461,
        1494,
        1500,
        1501,
        1503,
        1521,
        1524,
        1533,
        1556,
        1580,
        1583,
        1594,
        1600,
        1641,
        1658,
        1666,
        1687,
        1688,
        1700,
        1717,
        1718,
        1719,
        1720,
        1721,
        1723,
        1755,
        1761,
        1782,
        1783,
        1801,
        1805,
        1812,
        1839,
        1840,
        1862,
        1863,
        1864,
        1875,
        1900,
        1914,
        1935,
        1947,
        1971,
        1972,
        1974,
        1984,
        1998,
        1999,
        2000,
        2001,
        2002,
        2003,
        2004,
        2005,
        2006,
        2007,
        2008,
        2009,
        2010,
        2013,
        2020,
        2021,
        2022,
        2030,
        2033,
        2034,
        2035,
        2038,
        2040,
        2041,
        2042,
        2043,
        2045,
        2046,
        2047,
        2048,
        2049,
        2065,
        2068,
        2099,
        2100,
        2103,
        2105,
        2106,
        2107,
        2111,
        2119,
        2121,
        2126,
        2135,
        2144,
        2160,
        2161,
        2170,
        2179,
        2190,
        2191,
        2196,
        2200,
        2222,
        2251,
        2260,
        2288,
        2301,
        2323,
        2366,
        2381,
        2382,
        2383,
        2393,
        2394,
        2399,
        2401,
        2492,
        2500,
        2522,
        2525,
        2557,
        2601,
        2602,
        2604,
        2605,
        2607,
        2608,
        2638,
        2701,
        2702,
        2710,
        2717,
        2718,
        2725,
        2800,
        2809,
        2811,
        2869,
        2875,
        2909,
        2910,
        2920,
        2967,
        2968,
        2998,
        3000,
        3001,
        3003,
        3005,
        3006,
        3007,
        3011,
        3013,
        3017,
        3030,
        3031,
        3050,
        3052,
        3071,
        3077,
        3128,
        3168,
        3211,
        3221,
        3260,
        3261,
        3268,
        3269,
        3283,
        3300,
        3301,
        3306,
        3322,
        3323,
        3324,
        3325,
        3333,
        3351,
        3367,
        3369,
        3370,
        3371,
        3372,
        3389,
        3390,
        3404,
        3476,
        3493,
        3517,
        3527,
        3546,
        3551,
        3580,
        3659,
        3689,
        3690,
        3703,
        3737,
        3766,
        3784,
        3800,
        3801,
        3809,
        3814,
        3826,
        3827,
        3828,
        3851,
        3869,
        3871,
        3878,
        3880,
        3889,
        3905,
        3914,
        3918,
        3920,
        3945,
        3971,
        3986,
        3995,
        3998,
        4000,
        4001,
        4002,
        4003,
        4004,
        4005,
        4006,
        4045,
        4111,
        4125,
        4126,
        4129,
        4224,
        4242,
        4279,
        4321,
        4343,
        4443,
        4444,
        4445,
        4446,
        4449,
        4550,
        4567,
        4662,
        4848,
        4899,
        4900,
        4998,
        5000,
        5001,
        5002,
        5003,
        5004,
        5009,
        5030,
        5033,
        5050,
        5051,
        5054,
        5060,
        5061,
        5080,
        5087,
        5100,
        5101,
        5102,
        5120,
        5190,
        5200,
        5214,
        5221,
        5222,
        5225,
        5226,
        5269,
        5280,
        5298,
        5357,
        5405,
        5414,
        5431,
        5432,
        5440,
        5500,
        5510,
        5544,
        5550,
        5555,
        5560,
        5566,
        5631,
        5633,
        5666,
        5678,
        5679,
        5718,
        5730,
        5800,
        5801,
        5802,
        5810,
        5811,
        5815,
        5822,
        5825,
        5850,
        5859,
        5862,
        5877,
        5900,
        5901,
        5902,
        5903,
        5904,
        5906,
        5907,
        5910,
        5911,
        5915,
        5922,
        5925,
        5950,
        5952,
        5959,
        5960,
        5961,
        5962,
        5963,
        5987,
        5988,
        5989,
        5998,
        5999,
        6000,
        6001,
        6002,
        6003,
        6004,
        6005,
        6006,
        6007,
        6009,
        6025,
        6059,
        6100,
        6101,
        6106,
        6112,
        6123,
        6129,
        6156,
        6346,
        6389,
        6502,
        6510,
        6543,
        6547,
        6565,
        6566,
        6567,
        6580,
        6646,
        6666,
        6667,
        6668,
        6669,
        6689,
        6692,
        6699,
        6779,
        6788,
        6789,
        6792,
        6839,
        6881,
        6901,
        6969,
        7000,
        7001,
        7002,
        7004,
        7007,
        7019,
        7025,
        7070,
        7100,
        7103,
        7106,
        7200,
        7201,
        7402,
        7435,
        7443,
        7496,
        7512,
        7625,
        7627,
        7676,
        7741,
        7777,
        7778,
        7800,
        7911,
        7920,
        7921,
        7937,
        7938,
        7999,
        8000,
        8001,
        8002,
        8007,
        8008,
        8009,
        8010,
        8011,
        8021,
        8022,
        8031,
        8042,
        8045,
        8080,
        8081,
        8082,
        8083,
        8084,
        8085,
        8086,
        8087,
        8088,
        8089,
        8090,
        8093,
        8099,
        8100,
        8180,
        8181,
        8192,
        8193,
        8194,
        8200,
        8222,
        8254,
        8290,
        8291,
        8292,
        8300,
        8333,
        8383,
        8400,
        8402,
        8443,
        8500,
        8600,
        8649,
        8651,
        8652,
        8654,
        8701,
        8800,
        8873,
        8888,
        8899,
        8994,
        9000,
        9001,
        9002,
        9003,
        9009,
        9010,
        9011,
        9040,
        9050,
        9071,
        9080,
        9081,
        9090,
        9091,
        9099,
        9100,
        9101,
        9102,
        9103,
        9110,
        9111,
        9200,
        9207,
        9220,
        9290,
        9415,
        9418,
        9485,
        9500,
        9502,
        9503,
        9535,
        9575,
        9593,
        9594,
        9595,
        9618,
        9666,
        9876,
        9877,
        9878,
        9898,
        9900,
        9917,
        9929,
        9943,
        9944,
        9968,
        9998,
        9999,
        10000,
        10001,
        10002,
        10003,
        10004,
        10009,
        10010,
        10012,
        10024,
        10025,
        10082,
        10180,
        10215,
        10243,
        10566,
        10616,
        10617,
        10621,
        10626,
        10628,
        10629,
        10778,
        11110,
        11111,
        11967,
        12000,
        12174,
        12265,
        12345,
        13456,
        13722,
        13782,
        13783,
        14000,
        14238,
        14441,
        14442,
        15000,
        15002,
        15003,
        15004,
        15660,
        15742,
        16000,
        16001,
        16012,
        16016,
        16018,
        16080,
        16113,
        16992,
        16993,
        17877,
        17988,
        18040,
        18101,
        18988,
        19101,
        19283,
        19315,
        19350,
        19780,
        19801,
        19842,
        20000,
        20005,
        20031,
        20221,
        20222,
        20828,
        21571,
        22939,
        23502,
        24444,
        24800,
        25734,
        25735,
        26214,
        27000,
        27352,
        27353,
        27355,
        27356,
        27715,
        28201,
        30000,
        30718,
        30951,
        31038,
        31337,
        32768,
        32769,
        32770,
        32771,
        32772,
        32773,
        32774,
        32775,
        32776,
        32777,
        32778,
        32779,
        32780,
        32781,
        32782,
        32783,
        32784,
        32785,
        33354,
        33899,
        34571,
        34572,
        34573,
        35500,
        38292,
        40193,
        40911,
        41511,
        42510,
        44176,
        44442,
        44443,
        44501,
        45100,
        48080,
        49152,
        49153,
        49154,
        49155,
        49156,
        49157,
        49158,
        49159,
        49160,
        49161,
        49163,
        49165,
        49167,
        49175,
        49176,
        49400,
        49999,
        50000,
        50001,
        50002,
        50003,
        50006,
        50300,
        50389,
        50500,
        50636,
        50800,
        51103,
        51493,
        52673,
        52822,
        52848,
        52869,
        54045,
        54328,
        55055,
        55056,
        55555,
        55600,
        56737,
        56738,
        57294,
        57797,
        58080,
        60020,
        60443,
        61532,
        61900,
        62078,
        63331,
        64623,
        64680,
        65000,
        65129,
        65389,
    ],
}

# ---------------------------------------------------------------------------
# Protocol-Specific Probes for Service Detection
# ---------------------------------------------------------------------------

PROTOCOL_PROBES = {
    21: b"",  # FTP: server sends banner first
    22: b"",  # SSH: server sends banner first
    23: b"",  # Telnet: server sends banner first
    25: b"EHLO hostvigil.local\r\n",
    53: b"",  # DNS: no banner
    80: b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    110: b"",  # POP3: server sends banner first
    111: b"",  # RPC: binary protocol
    135: b"",  # MSRPC: binary protocol
    139: b"",  # NetBIOS
    143: b"",  # IMAP: server sends banner first
    389: b"",  # LDAP: binary protocol
    443: b"",  # HTTPS: TLS handshake needed
    445: b"",  # SMB: binary protocol
    465: b"EHLO hostvigil.local\r\n",
    514: b"",  # Syslog
    587: b"EHLO hostvigil.local\r\n",
    636: b"",  # LDAPS
    993: b"",  # IMAPS
    995: b"",  # POP3S
    1080: b"\x05\x01\x00",  # SOCKS5 greeting
    1433: b"",  # MSSQL: binary protocol
    1521: b"",  # Oracle: binary protocol
    2049: b"",  # NFS
    2375: b"GET /version HTTP/1.0\r\nHost: localhost\r\n\r\n",
    2376: b"",  # Docker TLS
    3306: b"",  # MySQL: server sends greeting
    3389: b"",  # RDP: binary protocol
    5432: b"",  # PostgreSQL: binary protocol
    5900: b"",  # VNC: server sends version
    5985: b"GET /wsman HTTP/1.0\r\nHost: localhost\r\n\r\n",
    5986: b"",  # WinRM HTTPS
    6379: b"PING\r\n",  # Redis
    8080: b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    8443: b"",  # HTTPS alt
    8888: b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    9090: b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    9200: b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",  # Elasticsearch
    9300: b"",  # Elasticsearch transport
    11211: b"version\r\n",  # Memcached
    27017: b"",  # MongoDB: binary protocol
}

# Service fingerprint patterns (substring matching on banner)
# Order matters: more specific patterns should come first in the list.
SERVICE_FINGERPRINTS = {
    "SSH": ["SSH-", "OpenSSH", "dropbear"],
    "HTTP": ["HTTP/", "Apache", "nginx", "Microsoft-IIS", "lighttpd"],
    "SMTP": ["ESMTP", "Postfix", "Sendmail", "Exchange", "SMTP"],
    "FTP": ["FTP", "vsFTPd", "ProFTPD", "FileZilla", "Pure-FTPd"],
    "MySQL": ["mysql", "MariaDB"],
    "PostgreSQL": ["PostgreSQL", "FATAL"],
    "Redis": ["+PONG", "redis_version", "-NOAUTH"],
    "MongoDB": ["MongoDB", "mongod"],
    "RDP": ["\x03\x00"],
    "VNC": ["RFB "],
    "POP3": ["+OK", "POP3"],
    "IMAP": ["* OK", "IMAP"],
    "Telnet": ["\xff\xfd", "\xff\xfb"],
    "DNS": [],
    "LDAP": [],
    "SMB": ["\x00\x00\x00"],
    "Elasticsearch": ["cluster_name", "elasticsearch", "opensearch"],
    "Docker": ["ApiVersion", "docker"],
    "Memcached": ["VERSION"],
    "SOCKS": ["\x05\x00"],
    "WinRM": ["wsman", "WinRM"],
}

# Default port-to-service mapping (fallback when banner is empty)
PORT_SERVICE_MAP = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    88: "Kerberos",
    110: "POP3",
    111: "RPC",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "Syslog",
    587: "SMTP-Submission",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS",
    1433: "MSSQL",
    1521: "Oracle",
    2049: "NFS",
    2375: "Docker",
    2376: "Docker-TLS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    5985: "WinRM",
    5986: "WinRM-TLS",
    6379: "Redis",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt",
    9090: "HTTP-Alt",
    9200: "Elasticsearch",
    9300: "Elasticsearch-Transport",
    11211: "Memcached",
    27017: "MongoDB",
}


class StealthScanner:
    """Enhanced stealth port scanner with IDS evasion capabilities."""

    def __init__(self, config: dict, db_path: str):
        """Initialize the stealth scanner.

        Args:
            config: Scanner configuration dictionary (from config.yaml stealth + scanner sections).
            db_path: Path to the SQLite database file.
        """
        self.config = config
        self.db_path = db_path

        # Per-host last-probe timestamp for inter-host rate limiting.
        # Replaces the old per-host Lock serialization: ports on the same host
        # can now overlap across threads; we only enforce a minimum wall-clock
        # gap between consecutive probes *to the same host*.
        self._host_last_probe: Dict[str, float] = {}
        self._host_locks: Dict[str, threading.Lock] = {}  # real per-host locks
        self._host_probe_lock = threading.Lock()  # guards _host_last_probe dict

        # RST tracking for adaptive throttling: {ip: [timestamp, ...]}
        self.rst_tracker: Dict[str, List[float]] = {}
        self._rst_lock = threading.Lock()

        # Adaptive delay multipliers per host
        self._delay_multipliers: Dict[str, float] = {}

        # Scan statistics
        self.scan_stats = {"total": 0, "open": 0, "closed": 0, "filtered": 0}
        self._stats_lock = threading.Lock()

        # SQLite connection guard. Banner grabs run from worker threads, so
        # the shared connection must be cross-thread and serialized.
        self._db_lock = threading.Lock()

        # Configuration extraction with defaults
        stealth_cfg = config.get("stealth", {})
        scanner_cfg = config.get("scanner", {})

        self.min_delay = stealth_cfg.get("min_delay", 10.0)
        self.max_delay = stealth_cfg.get("max_delay", 45.0)
        self.max_threads = stealth_cfg.get("max_threads", 3)
        self.jitter_factor = stealth_cfg.get("jitter_factor", 0.3)
        self.use_fragmentation = stealth_cfg.get("packet_fragmentation", True)
        self.randomize_order = stealth_cfg.get("randomize_scan_order", True)
        self.ttl_manipulation = stealth_cfg.get("ttl_manipulation", True)
        self.decoy_ips = stealth_cfg.get("decoy_ips", [])

        # Inter-port gap within a single host (ms → seconds).
        # Much smaller than min_delay: just enough to avoid a burst of
        # simultaneous SYNs to the same host triggering port-scan heuristics.
        # Default 150 ms.  Configurable via stealth.inter_port_delay_ms.
        self.inter_port_delay = stealth_cfg.get("inter_port_delay_ms", 150) / 1000.0

        # ---------------------------------------------------------------
        # Probe timeout vs banner timeout are now separate:
        #   connect_timeout — how long to wait for TCP SYN-ACK (LAN ≈ 0.5s)
        #   banner_timeout  — how long to wait for banner data after connect
        # Legacy 'timeout' key still accepted and used for both if present.
        # ---------------------------------------------------------------
        legacy_timeout = scanner_cfg.get("timeout", None)
        self.connect_timeout = scanner_cfg.get("connect_timeout", legacy_timeout if legacy_timeout is not None else 0.5)
        self.banner_timeout = scanner_cfg.get("banner_timeout", legacy_timeout if legacy_timeout is not None else 2.0)
        # Keep self.timeout as an alias so existing callers (_syn_scan etc.) still work
        self.timeout = self.connect_timeout

        self.banner_grab_enabled = scanner_cfg.get("banner_grab", True)
        self.service_detection_enabled = scanner_cfg.get("service_detection", True)

        # Two-phase scanning: when enabled, all SYNs are fired in a fast burst
        # first (inter_port_delay gap only), then banner grabs run after with
        # stealth inter-host delays.  Dramatically faster on LANs while keeping
        # the banner-grab phase quiet.  Requires scan_type='syn' + scapy.
        # Falls back to normal mode when connect scan is used.
        self.two_phase_scan = scanner_cfg.get("two_phase_scan", True)

        # Scan window configuration (24h format)
        self.scan_window_enabled = stealth_cfg.get("scan_window_enabled", False)
        self.scan_window_start = stealth_cfg.get("scan_window_start", 8)  # 8 AM
        self.scan_window_end = stealth_cfg.get("scan_window_end", 18)  # 6 PM

        # RST threshold for adaptive backoff
        self.rst_threshold = stealth_cfg.get("rst_threshold", 3)
        self.rst_window_seconds = stealth_cfg.get("rst_window_seconds", 60)
        self.rst_backoff_multiplier = stealth_cfg.get("rst_backoff_multiplier", 3.0)

        # ---------------------------------------------------------------
        # Auto-detect elevated privileges and upgrade to SYN scan.
        # SYN scan never completes the TCP handshake so it never appears in
        # application-layer logs (sshd, nginx, etc.).  It is also faster
        # because there is no ACK round-trip or graceful close.
        # Config scan_type='connect' overrides this auto-detection.
        # ---------------------------------------------------------------
        configured_scan_type = scanner_cfg.get("scan_type", "auto")
        if configured_scan_type == "auto" or configured_scan_type not in ("connect", "syn"):
            if SCAPY_AVAILABLE and self._is_elevated():
                self.scan_type = "syn"
                logger.info(
                    "StealthScanner: elevated privileges detected — auto-selected SYN scan (stealthier, faster)"
                )
            else:
                self.scan_type = "connect"
                if not SCAPY_AVAILABLE:
                    logger.info("StealthScanner: scapy unavailable — using connect scan")
                else:
                    logger.info(
                        "StealthScanner: not elevated — using connect scan "
                        "(set scan_type: syn and run as root/admin for SYN scan)"
                    )
        else:
            self.scan_type = configured_scan_type
            if self.scan_type == "syn" and not SCAPY_AVAILABLE:
                logger.warning("scan_type: syn requested but scapy unavailable — falling back to connect scan")
                self.scan_type = "connect"
            elif self.scan_type == "syn" and not self._is_elevated():
                logger.warning("scan_type: syn requested but not running as root/admin — falling back to connect scan")
                self.scan_type = "connect"

        logger.info(
            "StealthScanner initialized: scan_type=%s, threads=%d, "
            "connect_timeout=%.2fs, banner_timeout=%.2fs, "
            "inter_port_delay=%.0fms, two_phase=%s, delay=%.1f-%.1fs",
            self.scan_type,
            self.max_threads,
            self.connect_timeout,
            self.banner_timeout,
            self.inter_port_delay * 1000,
            self.two_phase_scan,
            self.min_delay,
            self.max_delay,
        )

    @staticmethod
    def _is_elevated() -> bool:
        """Return True if the current process has root (Unix) or admin (Windows) privileges."""
        try:
            import os as _os

            if hasattr(_os, "geteuid"):
                return _os.geteuid() == 0  # Unix/Linux/macOS
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # Windows
        except Exception:
            return False

    def _get_host_lock(self, ip: str) -> threading.Lock:
        """Get or create a per-host lock for rate limiting.

        Returns a real lock shared by all callers for the same host so the
        UDP scan path (and any other caller) actually serializes per-host
        work. The TCP scan path uses _wait_inter_port_delay instead.
        """
        with self._host_probe_lock:
            return self._host_locks.setdefault(ip, threading.Lock())

    def _wait_inter_port_delay(self, ip: str) -> None:
        """Enforce a minimum inter-port gap for the same host.

        Unlike the old host lock (which serialised ALL ports), this only
        sleeps for the *remaining* time since the last probe to this host.
        Multiple threads can probe the same host concurrently as long as
        they space their probes >= inter_port_delay apart.
        """
        with self._host_probe_lock:
            now = time.time()
            last = self._host_last_probe.get(ip, 0.0)
            # Calculate the earliest time this probe should fire
            earliest = last + self.inter_port_delay
            gap = earliest - now
            # Reserve our slot: next probe must wait until after us
            self._host_last_probe[ip] = max(earliest, now)

        if gap > 0:
            time.sleep(gap)

    def scan_hosts(self, hosts: List[str], port_profile: str = "standard") -> List[Dict]:
        """Main entry point: scan a list of hosts with the given port profile.

        Two-phase mode (when scan_type='syn' and two_phase_scan=True):
          Phase 1 — fast SYN burst: all probes fired with only inter_port_delay
                    between consecutive probes to the same host.  Responses are
                    collected concurrently.  This keeps the burst short and
                    distributes load across hosts simultaneously.
          Phase 2 — stealth banner grab: only open ports are banner-grabbed,
                    with the full stealth inter-host delay applied between each
                    host so banner traffic blends into normal background noise.

        Single-phase mode (connect scan or two_phase_scan=False):
          Original behaviour: probe + optional banner grab run together,
          with the inter-host stealth delay applied between host transitions
          (not between every port on the same host).

        Args:
            hosts: List of IP addresses to scan.
            port_profile: One of 'quick', 'standard', 'full' or a custom list.

        Returns:
            List of result dictionaries with scan findings.
        """
        if self.scan_window_enabled and not self._is_scan_window():
            logger.info(
                "Outside scan window (%d:00-%d:00), skipping scan", self.scan_window_start, self.scan_window_end
            )
            return []

        ports = (
            port_profile
            if isinstance(port_profile, list)
            else PORT_PROFILES.get(port_profile, PORT_PROFILES["standard"])
        )

        targets: List[Tuple[str, int]] = [(host, port) for host in hosts for port in ports]
        if self.randomize_order:
            random.shuffle(targets)

        host_priority = {}
        try:
            self._ensure_connection()
            rows = self._conn.execute(
                "SELECT ip, priority_score, "
                "(SELECT COUNT(*) FROM ports WHERE host_id = hosts.id AND state='open' AND is_active=1) as open_ports "
                "FROM hosts WHERE is_active = 1"
            ).fetchall()
            for ip, db_score, open_ports in rows:
                host_priority[ip] = float(open_ports or 0) * 10.0 - float(db_score or 0)
        except Exception:
            pass

        if host_priority:
            targets.sort(key=lambda t: host_priority.get(t[0], 0.0), reverse=True)

        logger.info(
            "Starting scan: %d targets (%d hosts × %d ports), profile=%s, mode=%s, scan_type=%s",
            len(targets),
            len(hosts),
            len(ports),
            port_profile,
            "two-phase" if (self.two_phase_scan and self.scan_type == "syn") else "single-phase",
            self.scan_type,
        )

        if self.two_phase_scan and self.scan_type == "syn" and SCAPY_AVAILABLE:
            return self._scan_two_phase(targets)
        else:
            return self._scan_single_phase(targets)

    # ------------------------------------------------------------------
    # Two-phase scan (SYN burst → stealth banner grab)
    # ------------------------------------------------------------------

    def _scan_two_phase(self, targets: List[Tuple[str, int]]) -> List[Dict]:
        """Phase 1: fast SYN burst.  Phase 2: stealth banner grab on open ports.

        Phase 1 fires all SYN probes with only inter_port_delay between
        consecutive probes to the same host.  Threads across different hosts
        run fully in parallel — no waiting on each other.

        Phase 2 processes open ports one host at a time, with the full
        inter-host stealth delay (min_delay..max_delay + jitter) applied
        between host transitions.  Banner grabs for ports on the *same* host
        run concurrently within the host's time slot.
        """
        probe_results: Dict[Tuple[str, int], Dict] = {}
        probe_lock = threading.Lock()

        # ---- Phase 1: SYN burst ----------------------------------------
        logger.info("Two-phase scan — Phase 1: SYN burst (%d targets)", len(targets))

        def _probe(target: Tuple[str, int]) -> Optional[Dict]:
            ip, port = target
            self._wait_inter_port_delay(ip)
            self._adaptive_throttle(ip)

            result = self._syn_scan(ip, port)

            with self._stats_lock:
                self.scan_stats["total"] += 1
                state = result.get("state", "filtered")
                if state in self.scan_stats:
                    self.scan_stats[state] += 1

            return result

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(_probe, t): t for t in targets}
            for future in as_completed(futures):
                t = futures[future]
                try:
                    r = future.result()
                    if r:
                        with probe_lock:
                            probe_results[t] = r
                except Exception as e:
                    logger.debug("Phase-1 probe error %s:%d: %s", t[0], t[1], e)

        # Collect open ports grouped by host
        open_by_host: Dict[str, List[int]] = {}
        for (ip, port), r in probe_results.items():
            if r.get("state") == "open":
                open_by_host.setdefault(ip, []).append(port)

        open_count = sum(len(v) for v in open_by_host.values())
        logger.info(
            "Two-phase scan — Phase 1 complete: %d open ports across %d hosts",
            open_count,
            len(open_by_host),
        )
        self._flush_db()

        # ---- Phase 2: stealth banner grab ------------------------------
        logger.info("Two-phase scan — Phase 2: banner grab (%d open ports)", open_count)
        results: List[Dict] = []

        host_list = list(open_by_host.keys())
        if self.randomize_order:
            random.shuffle(host_list)

        for idx, ip in enumerate(host_list):
            open_ports = open_by_host[ip]

            # Stealth inter-host delay (skip before the very first host)
            if idx > 0:
                delay = self._get_inter_host_delay(ip)
                logger.debug("Phase-2 inter-host delay before %s: %.1fs", ip, delay)
                time.sleep(delay)

            # Banner grab all open ports for this host concurrently
            # (same host, different ports — a client opening multiple connections
            # simultaneously is completely normal behaviour)
            def _grab(port: int, _ip: str = ip) -> Dict:
                banner = ""
                service = ""
                if self.banner_grab_enabled:
                    banner = self._grab_banner(_ip, port)
                if self.service_detection_enabled:
                    service = self._detect_service(port, banner)
                r = probe_results.get((_ip, port), {"ip": _ip, "port": port, "state": "open", "protocol": "tcp"})
                r["banner"] = banner
                r["service"] = service
                self._store_result(_ip, port, "open", service, banner)
                with self._db_lock:
                    if hasattr(self, "_conn") and self._conn:
                        try:
                            self._conn.execute(
                                "UPDATE hosts SET priority_score = priority_score + 10 WHERE ip = ?", (_ip,)
                            )
                        except Exception:
                            pass
                logger.info("OPEN %s:%d (%s) %s", _ip, port, service or "unknown", banner[:50] if banner else "")
                return r

            with ThreadPoolExecutor(max_workers=min(len(open_ports), 8)) as ex:
                for r in ex.map(_grab, open_ports):
                    results.append(r)

        logger.info("Two-phase scan complete: %d open ports found. Stats: %s", len(results), self.scan_stats)
        self._flush_db()
        return results

    # ------------------------------------------------------------------
    # Single-phase scan (connect or syn without two-phase)
    # ------------------------------------------------------------------

    def _scan_single_phase(self, targets: List[Tuple[str, int]]) -> List[Dict]:
        """Original single-phase scan with inter-host stealth delays.

        Improvement over the old design: the stealth delay is applied between
        host *transitions* rather than between every port probe.  Multiple
        ports on the same host are separated only by inter_port_delay.
        Banner grab runs OUTSIDE the rate-limiting section so it never
        blocks other threads from probing.
        """
        results: List[Dict] = []
        results_lock = threading.Lock()

        # Track which host each thread last probed to enforce inter-host delay
        _thread_last_host: Dict[int, str] = {}
        _thread_lock = threading.Lock()

        def _scan_target(target: Tuple[str, int]) -> Optional[Dict]:
            ip, port = target
            tid = threading.get_ident()

            # Inter-host stealth delay: only when this thread switches to a new host
            with _thread_lock:
                last_host = _thread_last_host.get(tid)
                _thread_last_host[tid] = ip

            if last_host and last_host != ip:
                delay = self._get_inter_host_delay(ip)
                time.sleep(delay)

            # Minimal inter-port gap for same host (replaces full host lock)
            self._wait_inter_port_delay(ip)
            self._adaptive_throttle(ip)

            # Probe
            if self.scan_type == "syn" and SCAPY_AVAILABLE:
                result = self._syn_scan(ip, port)
            else:
                result = self._connect_scan(ip, port)

            with self._stats_lock:
                self.scan_stats["total"] += 1
                state = result.get("state", "filtered")
                if state in self.scan_stats:
                    self.scan_stats[state] += 1

            # ----------------------------------------------------------------
            # Banner grab runs OUTSIDE the rate-limiting section.
            # The lock (host_probe tracking) has already been released above;
            # banner traffic is a normal client connection and does not need
            # to be serialised with the probe stream.
            # ----------------------------------------------------------------
            if result.get("state") == "open":
                banner = ""
                service = ""
                if self.banner_grab_enabled:
                    banner = self._grab_banner(ip, port)
                if self.service_detection_enabled:
                    service = self._detect_service(port, banner)
                result["banner"] = banner
                result["service"] = service
                self._store_result(ip, port, "open", service, banner)
                logger.info("OPEN %s:%d (%s) %s", ip, port, service or "unknown", banner[:50] if banner else "")

            return result

        CHUNK = 2000
        for chunk_start in range(0, len(targets), CHUNK):
            chunk = targets[chunk_start : chunk_start + CHUNK]
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = {executor.submit(_scan_target, t): t for t in chunk}
                for future in as_completed(futures):
                    try:
                        r = future.result()
                        if r and r.get("state") == "open":
                            with results_lock:
                                results.append(r)
                    except Exception as e:
                        t = futures[future]
                        logger.debug("Scan error for %s:%d: %s", t[0], t[1], e)
            self._flush_db()

        logger.info("Scan complete: %d open ports found. Stats: %s", len(results), self.scan_stats)
        self._flush_db()
        return results

    def _connect_scan(self, ip: str, port: int) -> Dict:
        """Standard TCP connect scan.

        Performs a full TCP three-way handshake. Does not require elevated
        privileges but is more detectable than SYN scan (handshake appears in
        application-layer logs).

        Uses connect_timeout (default 0.5s) — sufficient for LAN hosts and
        halves wait time vs the old 1.5s default on filtered ports.

        Args:
            ip: Target IP address.
            port: Target port number.

        Returns:
            Dictionary with ip, port, state ('open', 'closed', 'filtered').
        """
        result = {"ip": ip, "port": port, "state": "filtered", "protocol": "tcp"}

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(self.connect_timeout)

            # TTL manipulation: randomize to appear as different hop distances
            if self.ttl_manipulation:
                ttl = random.randint(48, 128)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

            conn_result = sock.connect_ex((ip, port))

            if conn_result == 0:
                result["state"] = "open"
            elif conn_result in (111, 10061):  # ECONNREFUSED (Linux=111, Windows=10061)
                result["state"] = "closed"
                self._record_rst(ip)
            else:
                # Timeout (110/10060), network unreachable, host unreachable, etc.
                result["state"] = "filtered"

        except socket.timeout:
            result["state"] = "filtered"
        except ConnectionRefusedError:
            result["state"] = "closed"
            self._record_rst(ip)
        except OSError as e:
            logger.debug("Connect scan error %s:%d: %s", ip, port, e)
            result["state"] = "filtered"
        finally:
            sock.close()

        return result

    def _syn_scan(self, ip: str, port: int) -> Dict:
        """SYN half-open scan using scapy (requires elevated privileges).

        Sends a SYN packet and analyzes the response:
        - SYN/ACK = open (sends RST to close without completing handshake)
        - RST/ACK = closed
        - No response = filtered

        When packet_fragmentation is enabled, the TCP SYN is split across two
        IP fragments. Fragment 1 carries the IP header + first 8 bytes of the
        TCP header (src/dst port + sequence number). Fragment 2 carries the
        remaining 12 bytes (ack, data offset, flags, window, checksum, urgent).
        Most stateless DPI/IDS engines inspect each fragment independently and
        miss the SYN flag which lives in the second fragment, while the target
        OS reassembles them normally before handing up to TCP.

        Also supports decoy IPs and TTL manipulation.

        Args:
            ip: Target IP address.
            port: Target port number.

        Returns:
            Dictionary with ip, port, state.
        """
        result = {"ip": ip, "port": port, "state": "filtered", "protocol": "tcp"}

        if not SCAPY_AVAILABLE:
            logger.warning("Scapy not available, falling back to connect scan")
            return self._connect_scan(ip, port)

        try:
            from scapy.all import fragment as scapy_fragment
        except ImportError:
            scapy_fragment = None

        try:
            # Suppress scapy output
            conf.verb = 0

            # Build IP layer with optional TTL manipulation
            ttl = random.randint(48, 128) if self.ttl_manipulation else 64
            src_port = int(RandShort())
            seq_num = random.randint(1000, 9000000)

            tcp_layer = TCP(sport=src_port, dport=port, flags="S", seq=seq_num)

            # ------------------------------------------------------------------
            # IP Fragmentation
            # Splits the assembled SYN packet into two IP fragments:
            #   Fragment 1 (offset 0,  MF=1): IP hdr + TCP bytes 0-7
            #                                  (sport, dport, seq — no flags)
            #   Fragment 2 (offset 8,  MF=0): IP hdr + TCP bytes 8-19
            #                                  (ack, dataofs, flags, window,
            #                                   checksum, urgptr — SYN flag here)
            #
            # fragsize must be a multiple of 8 (IP fragment offset unit).
            # scapy's fragment(fragsize=8) produces exactly this split for a
            # 20-byte TCP header with no options.
            # ------------------------------------------------------------------
            use_frag = self.use_fragmentation and scapy_fragment is not None

            ip_layer = IP(dst=ip, ttl=ttl)

            if use_frag:
                # Build the complete packet first so scapy can compute checksums
                # before we fragment (fragments carry the original checksum in
                # the second fragment — target OS verifies after reassembly).
                full_pkt = ip_layer / tcp_layer
                # fragsize=8 → each fragment payload is 8 bytes; TCP header
                # is 20 bytes so we get two fragments (8 + 12 bytes).
                fragments = scapy_fragment(full_pkt, fragsize=8)
                logger.debug(
                    "SYN scan (fragmented): %s:%d → %d fragments",
                    ip,
                    port,
                    len(fragments),
                )
            else:
                fragments = None

            # ------------------------------------------------------------------
            # Send decoy packets first (if configured).
            # Decoys are always sent as unfragmented SYNs — fragmenting decoys
            # too would double the fragment count and increase noise.
            # ------------------------------------------------------------------
            if self.decoy_ips:
                for decoy_ip in self.decoy_ips:
                    decoy_pkt = IP(src=decoy_ip, dst=ip, ttl=random.randint(48, 128)) / TCP(
                        sport=int(RandShort()), dport=port, flags="S", seq=random.randint(1000, 9000000)
                    )
                    try:
                        send(decoy_pkt, verbose=0)
                    except Exception:
                        pass
                    time.sleep(random.uniform(0.01, 0.05))

            # ------------------------------------------------------------------
            # Send the real SYN (fragmented or plain) and wait for a response.
            # When fragmenting: send all-but-last fragments with send(), then
            # use sr1() on the final fragment to capture the response.  The
            # target will reassemble after the last fragment arrives.
            # ------------------------------------------------------------------
            if use_frag and fragments and len(fragments) >= 2:
                # Send leading fragments silently
                for frag in fragments[:-1]:
                    send(frag, verbose=0)
                    time.sleep(random.uniform(0.005, 0.02))  # tiny gap between frags
                # Last fragment — wait for the reassembled reply
                response = sr1(fragments[-1], timeout=self.timeout, verbose=0)
            else:
                # Normal unfragmented SYN
                response = sr1(ip_layer / tcp_layer, timeout=self.timeout, verbose=0)

            # ------------------------------------------------------------------
            # Interpret response
            # ------------------------------------------------------------------
            if response is None:
                result["state"] = "filtered"
            elif response.haslayer(TCP):
                tcp_flags = response[TCP].flags
                if tcp_flags == 0x12:  # SYN/ACK → port open
                    result["state"] = "open"
                    # Send RST to tear down the half-open connection cleanly
                    rst_pkt = IP(dst=ip, ttl=ttl) / TCP(sport=src_port, dport=port, flags="R", seq=response[TCP].ack)
                    send(rst_pkt, verbose=0)
                elif tcp_flags & 0x04:  # RST set → port closed
                    result["state"] = "closed"
                    self._record_rst(ip)
                else:
                    result["state"] = "filtered"
            else:
                result["state"] = "filtered"

        except PermissionError:
            logger.error("SYN scan requires elevated privileges. Falling back to connect scan.")
            return self._connect_scan(ip, port)
        except Exception as e:
            logger.debug("SYN scan error %s:%d: %s", ip, port, e)
            result["state"] = "filtered"

        return result

    def _grab_banner(self, ip: str, port: int) -> str:
        """Enhanced banner grabbing with protocol-specific probes.

        Runs OUTSIDE the rate-limiting / probe section so it never blocks
        other threads from firing probes.  Uses banner_timeout (default 2.0s)
        which is independent of the fast connect_timeout used for probing.

        Args:
            ip: Target IP address.
            port: Target port number.

        Returns:
            Banner string (may be empty if no response or binary protocol).
        """
        banner = ""
        probe = PROTOCOL_PROBES.get(port, b"")

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(self.banner_timeout)

            if self.ttl_manipulation:
                ttl = random.randint(48, 128)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

            sock.connect((ip, port))

            if not probe:
                time.sleep(0.3)
                try:
                    data = sock.recv(1024)
                    banner = self._safe_decode(data)
                except socket.timeout:
                    pass
            else:
                sock.sendall(probe)
                time.sleep(0.3)
                try:
                    data = sock.recv(4096)
                    banner = self._safe_decode(data)
                except socket.timeout:
                    pass

        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            logger.debug("Banner grab failed %s:%d: %s", ip, port, e)
        finally:
            sock.close()

        return banner.strip()

    @staticmethod
    def _safe_decode(data: bytes) -> str:
        """Safely decode bytes to string, handling binary data."""
        if not data:
            return ""
        try:
            # Try UTF-8 first
            text = data.decode("utf-8", errors="replace")
            # Remove null bytes and control characters (keep newlines/tabs)
            cleaned = "".join(
                c
                for c in text
                if c == "\n" or c == "\r" or c == "\t" or (ord(c) >= 32 and ord(c) < 127) or ord(c) > 127
            )
            return cleaned[:512]  # Limit banner length
        except Exception:
            # Fall back to hex representation for binary protocols
            return data[:64].hex()

    def _detect_service(self, port: int, banner: str) -> str:
        """Identify service from port number and banner fingerprint.

        Uses a two-pass approach:
        1. Try to match banner content against known fingerprints.
        2. Fall back to port-based service mapping.

        Args:
            port: Port number.
            banner: Banner string from the service.

        Returns:
            Service name string.
        """
        # First pass: fingerprint-based detection from banner
        if banner:
            banner_upper = banner.upper()
            for service_name, patterns in SERVICE_FINGERPRINTS.items():
                for pattern in patterns:
                    if pattern.upper() in banner_upper:
                        return service_name

            # Additional heuristics for common responses
            if banner.startswith("HTTP/") or "Server:" in banner:
                return "HTTP"
            if "SSH-" in banner:
                return "SSH"
            if "+OK" in banner or "+PONG" in banner:
                if port == 6379:
                    return "Redis"
                return "POP3"
            if "220 " in banner:
                # Disambiguate FTP vs SMTP by port and content
                if port in (25, 465, 587) or "SMTP" in banner_upper or "MAIL" in banner_upper:
                    return "SMTP"
                if port == 21 or "FTP" in banner_upper:
                    return "FTP"
                # Default: use port mapping
                return PORT_SERVICE_MAP.get(port, "unknown")
            if "mysql" in banner.lower() or "mariadb" in banner.lower():
                return "MySQL"

        # Second pass: port-based fallback
        return PORT_SERVICE_MAP.get(port, "unknown")

    def _record_rst(self, ip: str):
        """Record a RST/connection refused event for adaptive throttling."""
        with self._rst_lock:
            now = time.time()
            if ip not in self.rst_tracker:
                self.rst_tracker[ip] = []
            self.rst_tracker[ip].append(now)

    def _adaptive_throttle(self, ip: str):
        """Check RST rate and adjust timing if IDS detection is suspected.

        If more than rst_threshold RSTs are received from the same host
        within the rst_window_seconds window, the delay multiplier for that
        host is increased by rst_backoff_multiplier.

        Args:
            ip: Target IP address to check throttling for.
        """
        with self._rst_lock:
            if ip not in self.rst_tracker:
                return

            now = time.time()
            window_start = now - self.rst_window_seconds

            # Prune old entries outside the window
            self.rst_tracker[ip] = [ts for ts in self.rst_tracker[ip] if ts > window_start]

            # Clean up empty tracker entries to prevent memory leak
            if not self.rst_tracker[ip]:
                del self.rst_tracker[ip]
                return

            rst_count = len(self.rst_tracker[ip])

            if rst_count > self.rst_threshold:
                # Increase delay multiplier for this host
                current_mult = self._delay_multipliers.get(ip, 1.0)
                new_mult = min(current_mult * self.rst_backoff_multiplier, 15.0)
                self._delay_multipliers[ip] = new_mult

                logger.warning(
                    "Adaptive throttle: %s has %d RSTs in %ds window, delay multiplier now %.1fx",
                    ip,
                    rst_count,
                    self.rst_window_seconds,
                    new_mult,
                )

                # Clear the tracker to avoid repeated escalation
                self.rst_tracker[ip] = []
            elif rst_count <= self.rst_threshold:
                # Below threshold — gradually reduce multiplier when host is responding normally
                current_mult = self._delay_multipliers.get(ip, 1.0)
                if current_mult > 1.0:
                    self._delay_multipliers[ip] = max(1.0, current_mult * 0.8)

    def _get_inter_host_delay(self, ip: str) -> float:
        """Calculate stealth delay to apply when transitioning to a new host.

        This is the full randomized stealth delay (min_delay..max_delay + jitter)
        and is only applied once per host-transition, not between every port
        on the same host.  Adaptive multiplier for high-RST hosts is included.

        Args:
            ip: Target IP (used to look up adaptive multiplier).

        Returns:
            Delay in seconds.
        """
        base_delay = random.uniform(self.min_delay, self.max_delay)
        jitter = base_delay * self.jitter_factor * random.uniform(-1.0, 1.0)
        delay = base_delay + jitter
        multiplier = self._delay_multipliers.get(ip, 1.0)
        delay *= multiplier
        return max(0.5, delay)

    def _get_delay(self, ip: str) -> float:
        """Alias for backward compatibility (UDP scan path uses this name)."""
        return self._get_inter_host_delay(ip)

    def _is_scan_window(self) -> bool:
        """Check if current time is within the configured scan window.

        The scan window is defined by scan_window_start and scan_window_end
        hours (in local time). Scanning during business hours helps blend
        with normal network traffic.

        Returns:
            True if current time is within the scan window, False otherwise.
        """
        if not self.scan_window_enabled:
            return True

        current_hour = datetime.now().hour

        if self.scan_window_start <= self.scan_window_end:
            # Normal window (e.g., 8-18)
            return self.scan_window_start <= current_hour < self.scan_window_end
        else:
            # Wrapping window (e.g., 22-6 for overnight)
            return current_hour >= self.scan_window_start or current_hour < self.scan_window_end

    def _ensure_connection(self):
        if not hasattr(self, "_conn") or self._conn is None:
            # check_same_thread=False: banner grabs run from worker threads.
            # All access is serialized via self._db_lock.
            self._conn = sqlite3.connect(self.db_path, timeout=30, check_same_thread=False)
            self._conn.execute("PRAGMA busy_timeout=30000")
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")

    def _store_result(self, ip: str, port: int, state: str, service: str, banner: str):
        now_iso = datetime.now(timezone.utc).isoformat()
        with self._db_lock:
            self._store_result_locked(ip, port, state, service, banner, now_iso)

    def _store_result_locked(self, ip: str, port: int, state: str, service: str, banner: str, now_iso: str):
        try:
            self._ensure_connection()
            cursor = self._conn.cursor()
            cursor.execute("SELECT id FROM hosts WHERE ip = ?", (ip,))
            row = cursor.fetchone()
            if row:
                host_id = row[0]
                cursor.execute(
                    "UPDATE hosts SET last_seen = ?, is_active = 1 WHERE id = ?",
                    (now_iso, host_id),
                )
            else:
                cursor.execute(
                    "INSERT INTO hosts (ip, first_seen, last_seen, discovery_method, is_active) VALUES (?, ?, ?, ?, 1)",
                    (ip, now_iso, now_iso, "port_scan"),
                )
                host_id = cursor.lastrowid

            cursor.execute(
                "SELECT id FROM ports WHERE host_id = ? AND port = ? AND protocol = 'tcp'",
                (host_id, port),
            )
            port_row = cursor.fetchone()
            if port_row:
                cursor.execute(
                    "UPDATE ports SET state = ?, service = ?, banner = ?, last_seen = ?, is_active = 1 WHERE id = ?",
                    (state, service, banner[:512] if banner else "", now_iso, port_row[0]),
                )
            else:
                cursor.execute(
                    "INSERT INTO ports (host_id, port, protocol, state, service, banner, "
                    "first_seen, last_seen, is_active) VALUES (?, ?, 'tcp', ?, ?, ?, ?, ?, 1)",
                    (host_id, port, state, service, banner[:512] if banner else "", now_iso, now_iso),
                )
        except sqlite3.Error as e:
            logger.debug("DB error storing %s:%d: %s", ip, port, e)
            try:
                self._conn.rollback()
                self._conn.close()
                self._conn = None
            except Exception:
                pass

    def _flush_db(self):
        if not (hasattr(self, "_conn") and self._conn):
            return
        with self._db_lock:
            try:
                self._conn.commit()
            except sqlite3.Error:
                pass

    def _close_db(self):
        if not (hasattr(self, "_conn") and self._conn):
            return
        with self._db_lock:
            try:
                self._conn.commit()
            except sqlite3.Error:
                pass
            try:
                self._conn.close()
            except sqlite3.Error:
                pass
            self._conn = None

    def get_scan_stats(self) -> Dict:
        """Return current scan statistics."""
        self._flush_db()
        with self._stats_lock:
            stats = dict(self.scan_stats)

        total = stats.get("total", 0)
        stats["open_rate"] = round(stats["open"] / total * 100, 2) if total > 0 else 0.0
        stats["hosts_tracked"] = len(self._host_last_probe)
        stats["throttled_hosts"] = sum(1 for m in self._delay_multipliers.values() if m > 1.0)
        return stats

    def reset_stats(self):
        """Reset scan statistics counters."""
        with self._stats_lock:
            self.scan_stats = {"total": 0, "open": 0, "closed": 0, "filtered": 0}
        self._delay_multipliers.clear()
        self.rst_tracker.clear()
        with self._host_probe_lock:
            self._host_last_probe.clear()
            self._host_locks.clear()
        self._close_db()
        logger.info("Scan statistics and adaptive state reset")


# ---------------------------------------------------------------------------
# UDP Port Profiles
# ---------------------------------------------------------------------------

UDP_PORT_PROFILES = {
    "quick": [53, 123, 161, 500, 1900],
    "standard": [53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 520, 1194, 1900, 4500, 5353],
    "full": [
        53,
        67,
        68,
        69,
        111,
        123,
        137,
        138,
        161,
        162,
        500,
        514,
        520,
        623,
        1194,
        1434,
        1604,
        1900,
        2049,
        4500,
        5060,
        5353,
        5632,
        11211,
        27960,
    ],
}

# ---------------------------------------------------------------------------
# UDP Protocol-Specific Probes
# ---------------------------------------------------------------------------

UDP_PROBES = {
    # DNS query for version.bind (CHAOS TXT)
    53: b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03",
    # NTP version request (mode 3, version 3)
    123: b"\xe3\x00\x03\xfa" + b"\x00" * 44,
    # SNMPv1 get-request for sysDescr.0 with 'public' community
    161: b"\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00",
    # NetBIOS NBSTAT query
    137: b"\x80\xf0\x00\x10\x00\x01\x00\x00\x00\x00\x00\x00\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01",
    # SSDP M-SEARCH
    1900: b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n',
    # mDNS query (same as DNS probe but targeting mDNS)
    5353: b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03",
}

# Default probe for ports without a specific payload
_UDP_DEFAULT_PROBE = b""


# ---------------------------------------------------------------------------
# UDP Scanning Methods (added to StealthScanner)
# ---------------------------------------------------------------------------


def _scan_udp_method(self, hosts: List[str], port_profile: str = "standard") -> List[Dict]:
    """UDP scan with stealth timing. Uses protocol-specific probes to elicit responses.

    UDP scanning is inherently slower and less reliable than TCP. A response
    confirms the port is open; ICMP port unreachable means closed; no response
    means open|filtered.

    Follows the same threading pattern as scan_hosts: ThreadPoolExecutor with
    per-host locks, adaptive throttling, randomized order, and jittered delays.

    Args:
        hosts: List of IP addresses to scan.
        port_profile: One of 'quick', 'standard', 'full' or a custom list.

    Returns:
        List of result dictionaries for ports identified as 'open'.
    """
    # Check scan window
    if self.scan_window_enabled and not self._is_scan_window():
        logger.info(
            "Outside scan window (%d:00-%d:00), skipping UDP scan", self.scan_window_start, self.scan_window_end
        )
        return []

    # Resolve port list
    if isinstance(port_profile, list):
        ports = port_profile
    else:
        ports = UDP_PORT_PROFILES.get(port_profile, UDP_PORT_PROFILES["standard"])

    # Build target list: all (host, port) combinations
    targets: List[Tuple[str, int]] = []
    for host in hosts:
        for port in ports:
            targets.append((host, port))

    # Randomize scan order for stealth
    if self.randomize_order:
        random.shuffle(targets)

    logger.info(
        "Starting UDP scan: %d targets (%d hosts x %d ports), profile=%s",
        len(targets),
        len(hosts),
        len(ports),
        port_profile,
    )

    results: List[Dict] = []
    results_lock = threading.Lock()

    # Track which host each thread last probed to enforce inter-host delay
    _thread_last_host: Dict[int, str] = {}
    _thread_lock = threading.Lock()

    def _scan_target(target: Tuple[str, int]) -> Optional[Dict]:
        ip, port = target
        tid = threading.get_ident()

        # Inter-host stealth delay: only when this thread switches to a new host
        with _thread_lock:
            last_host = _thread_last_host.get(tid)
            _thread_last_host[tid] = ip

        if last_host and last_host != ip:
            delay = self._get_inter_host_delay(ip)
            time.sleep(delay)

        # Minimal inter-port gap for same host (replaces old serialising lock)
        self._wait_inter_port_delay(ip)
        # Adaptive throttle check
        self._adaptive_throttle(ip)

        # Perform the UDP probe
        result = self._udp_probe(ip, port)

        # Update stats
        with self._stats_lock:
            self.scan_stats["total"] += 1
            state = result.get("state", "open|filtered")
            if state == "open":
                self.scan_stats["open"] += 1
            elif state == "closed":
                self.scan_stats["closed"] += 1
            else:
                self.scan_stats["filtered"] += 1

        # Store open ports in database
        if result.get("state") == "open":
            service = PORT_SERVICE_MAP.get(port, "unknown")
            banner = result.get("response_preview", "")
            result["service"] = service
            self._store_udp_result(ip, port, "open", service, banner)

            logger.info("UDP OPEN %s:%d (%s) %s", ip, port, service, banner[:50] if banner else "")

        return result

    # Execute with thread pool
    with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
        futures = {executor.submit(_scan_target, t): t for t in targets}
        for future in as_completed(futures):
            try:
                result = future.result()
                if result and result.get("state") == "open":
                    with results_lock:
                        results.append(result)
            except Exception as e:
                target = futures[future]
                logger.debug("UDP scan error for %s:%d: %s", target[0], target[1], e)

    logger.info("UDP scan complete: %d open ports found.", len(results))

    return results


def _udp_probe_method(self, ip: str, port: int) -> Dict:
    """Send a single UDP probe and analyze response.

    Sends the protocol-specific payload for the given port and waits for a
    response. Classification logic:
    - Response received -> 'open'
    - ICMP port unreachable (ConnectionRefusedError on Windows) -> 'closed'
    - Timeout with no response -> 'open|filtered'

    Args:
        ip: Target IP address.
        port: Target UDP port number.

    Returns:
        Dictionary with ip, port, protocol, state, and optional response_preview.
    """
    result = {
        "ip": ip,
        "port": port,
        "protocol": "udp",
        "state": "open|filtered",
        "response_preview": "",
    }

    # Get the protocol-specific probe payload
    probe_data = UDP_PROBES.get(port, _UDP_DEFAULT_PROBE)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(self.timeout + 1.0)

            # TTL manipulation for stealth
            if self.ttl_manipulation:
                ttl = random.randint(48, 128)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

            # Send the probe
            sock.sendto(probe_data, (ip, port))

            # Wait for response
            try:
                data, addr = sock.recvfrom(4096)
                if data:
                    result["state"] = "open"
                    # Store a preview of the response
                    result["response_preview"] = StealthScanner._safe_decode(data)
            except socket.timeout:
                # No response — could be open or filtered
                result["state"] = "open|filtered"
            except ConnectionRefusedError:
                # ICMP port unreachable received (common on Windows)
                result["state"] = "closed"
                self._record_rst(ip)
            except OSError as e:
                # On some systems, ICMP unreachable manifests as OSError
                error_str = str(e).lower()
                if "unreachable" in error_str or "refused" in error_str:
                    result["state"] = "closed"
                    self._record_rst(ip)
                else:
                    logger.debug("UDP probe OS error %s:%d: %s", ip, port, e)
                    result["state"] = "open|filtered"

        finally:
            sock.close()

    except Exception as e:
        logger.debug("UDP probe error %s:%d: %s", ip, port, e)
        result["state"] = "open|filtered"

    return result


def _store_udp_result_method(self, ip: str, port: int, state: str, service: str, banner: str):
    """Store UDP scan result in the SQLite database.

    Inserts or updates the ports table with protocol='udp'. Ensures the host
    exists in the hosts table.

    Args:
        ip: Host IP address.
        port: UDP port number.
        state: Port state ('open', 'closed', 'open|filtered').
        service: Detected service name.
        banner: Response preview text.
    """
    now_iso = datetime.now(timezone.utc).isoformat()

    try:
        conn = sqlite3.connect(self.db_path, timeout=30)
        try:
            conn.execute("PRAGMA busy_timeout=30000")
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            cursor = conn.cursor()

            # Ensure host exists in hosts table
            cursor.execute("SELECT id FROM hosts WHERE ip = ?", (ip,))
            row = cursor.fetchone()

            if row:
                host_id = row[0]
                cursor.execute(
                    "UPDATE hosts SET last_seen = ?, is_active = 1 WHERE id = ?",
                    (now_iso, host_id),
                )
            else:
                cursor.execute(
                    "INSERT INTO hosts (ip, first_seen, last_seen, discovery_method, is_active) VALUES (?, ?, ?, ?, 1)",
                    (ip, now_iso, now_iso, "udp_scan"),
                )
                host_id = cursor.lastrowid

            # Insert or update port record with protocol='udp'
            cursor.execute(
                "SELECT id FROM ports WHERE host_id = ? AND port = ? AND protocol = 'udp'",
                (host_id, port),
            )
            port_row = cursor.fetchone()

            if port_row:
                cursor.execute(
                    "UPDATE ports SET state = ?, service = ?, banner = ?, last_seen = ?, is_active = 1 WHERE id = ?",
                    (state, service, banner[:512] if banner else "", now_iso, port_row[0]),
                )
            else:
                cursor.execute(
                    "INSERT INTO ports (host_id, port, protocol, state, service, banner, "
                    "first_seen, last_seen, is_active) VALUES (?, ?, 'udp', ?, ?, ?, ?, ?, 1)",
                    (host_id, port, state, service, banner[:512] if banner else "", now_iso, now_iso),
                )

            conn.commit()
        finally:
            conn.close()

    except sqlite3.Error as e:
        logger.error("Database error storing UDP result for %s:%d: %s", ip, port, e)


# ---------------------------------------------------------------------------
# Monkey-patch UDP methods onto StealthScanner
# ---------------------------------------------------------------------------

StealthScanner.scan_udp = _scan_udp_method
StealthScanner._udp_probe = _udp_probe_method
StealthScanner._store_udp_result = _store_udp_result_method

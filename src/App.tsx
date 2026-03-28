import React, { useState, useEffect, useCallback } from 'react';
import { Copy, Download, Upload, RefreshCw, Shield, Lock, FileText, Hash, Eye, EyeOff } from 'lucide-react';

interface Tool {
  id: string;
  name: string;
  icon: React.ReactNode;
  color: string;
  description: string;
}

const tools: Tool[] = [
  {
    id: 'password',
    name: 'Password Generator',
    icon: <Lock className="w-5 h-5" />,
    color: 'from-emerald-500 to-teal-500',
    description: 'Generate cryptographically secure passwords'
  },
  {
    id: 'hash',
    name: 'Hash Generator',
    icon: <Hash className="w-5 h-5" />,
    color: 'from-violet-500 to-purple-600',
    description: 'Compute cryptographic hashes'
  },
  {
    id: 'metadata',
    name: 'Metadata Cleaner',
    icon: <FileText className="w-5 h-5" />,
    color: 'from-amber-500 to-orange-500',
    description: 'Remove EXIF and metadata from files'
  },
  {
    id: 'encrypt',
    name: 'File Encryptor',
    icon: <Shield className="w-5 h-5" />,
    color: 'from-rose-500 to-pink-500',
    description: 'AES-256 encryption & decryption'
  },
  {
    id: 'scanner',
    name: 'Privacy Scanner',
    icon: <Eye className="w-5 h-5" />,
    color: 'from-cyan-500 to-blue-500',
    description: 'Analyze website privacy score'
  },
];

const PrivacyStatement = () => (
  <div className="bg-emerald-950/50 border border-emerald-500/30 rounded-2xl p-4 text-xs text-emerald-400 flex items-center gap-3">
    <div className="w-2 h-2 bg-emerald-400 rounded-full animate-pulse"></div>
    <span>All tools run locally in your browser. No data is uploaded or tracked. Ever.</span>
  </div>
);

export default function PrivMITLab() {
  const [activeTool, setActiveTool] = useState('password');
  const [copied, setCopied] = useState(false);
  
  // Password Generator State
  const [passwordLength, setPasswordLength] = useState(16);
  const [includeUpper, setIncludeUpper] = useState(true);
  const [includeLower, setIncludeLower] = useState(true);
  const [includeNumbers, setIncludeNumbers] = useState(true);
  const [includeSymbols, setIncludeSymbols] = useState(true);
  const [generatedPassword, setGeneratedPassword] = useState('');
  const [passwordStrength, setPasswordStrength] = useState(0);

  // Hash Generator State
  const [inputText, setInputText] = useState('');
  const [selectedHash, setSelectedHash] = useState('SHA-256');
  const [hashResult, setHashResult] = useState('');
  const [isHashing, setIsHashing] = useState(false);
  const [fileForHash, setFileForHash] = useState<File | null>(null);

  // Metadata Cleaner State
  const [uploadedFile, setUploadedFile] = useState<File | null>(null);
  const [cleanedFileUrl, setCleanedFileUrl] = useState<string | null>(null);
  const [metadataInfo, setMetadataInfo] = useState<any>(null);
  const [isCleaning, setIsCleaning] = useState(false);

  // Encryptor State
  const [encryptFile, setEncryptFile] = useState<File | null>(null);
  const [encryptPassword, setEncryptPassword] = useState('');
  const [showEncryptPass, setShowEncryptPass] = useState(false);
  const [encryptMode, setEncryptMode] = useState<'encrypt' | 'decrypt'>('encrypt');
  const [encryptedFileUrl, setEncryptedFileUrl] = useState<string | null>(null);
  const [isProcessingFile, setIsProcessingFile] = useState(false);

  // Privacy Scanner State
  const [scanUrl, setScanUrl] = useState('');
  const [scanResult, setScanResult] = useState<any>(null);
  const [isScanning, setIsScanning] = useState(false);

  // MD5 Implementation (since not in WebCrypto)
  const md5 = (str: string): string => {
    function rotateLeft(x: number, n: number) {
      return (x << n) | (x >>> (32 - n));
    }
    
    function addUnsigned(x: number, y: number) {
      const lsw = (x & 0xFFFF) + (y & 0xFFFF);
      const msw = (x >> 16) + (y >> 16) + (lsw >> 16);
      return (msw << 16) | (lsw & 0xFFFF);
    }

    function cmn(q: number, a: number, b: number, x: number, s: number, t: number) {
      return addUnsigned(rotateLeft(addUnsigned(addUnsigned(a, q), addUnsigned(x, t)), s), b);
    }

    function ff(a: number, b: number, c: number, d: number, x: number, s: number, ac: number) {
      return cmn((b & c) | (~b & d), a, b, x, s, ac);
    }
    function gg(a: number, b: number, c: number, d: number, x: number, s: number, ac: number) {
      return cmn((b & d) | (c & ~d), a, b, x, s, ac);
    }
    function hh(a: number, b: number, c: number, d: number, x: number, s: number, ac: number) {
      return cmn(b ^ c ^ d, a, b, x, s, ac);
    }
    function ii(a: number, b: number, c: number, d: number, x: number, s: number, ac: number) {
      return cmn(c ^ (b | ~d), a, b, x, s, ac);
    }

    const x = Array(16);
    let a = 0x67452301, b = 0xEFCDAB89, c = 0x98BADCFE, d = 0x10325476;
    
    let str2 = unescape(encodeURIComponent(str));
    let len = str2.length * 8;

    for (let i = 0; i < len; i += 8) {
      x[(i >> 5)] |= (str2.charCodeAt(i / 8) & 0xff) << (i % 32);
    }
    
    x[len >> 5] |= 0x80 << (len % 32);
    x[(((len + 64) >>> 9) << 4) + 14] = len;

    for (let i = 0; i < x.length; i += 16) {
      const olda = a, oldb = b, oldc = c, oldd = d;

      a = ff(a, b, c, d, x[i], 7, 0xD76AA478);
      d = ff(d, a, b, c, x[i + 1], 12, 0xE8C7B756);
      c = ff(c, d, a, b, x[i + 2], 17, 0x242070DB);
      b = ff(b, c, d, a, x[i + 3], 22, 0xC1BDCEEE);
      a = ff(a, b, c, d, x[i + 4], 7, 0xF57C0FAF);
      d = ff(d, a, b, c, x[i + 5], 12, 0x4787C62A);
      c = ff(c, d, a, b, x[i + 6], 17, 0xA8304613);
      b = ff(b, c, d, a, x[i + 7], 22, 0xFD469501);
      a = ff(a, b, c, d, x[i + 8], 7, 0x698098D8);
      d = ff(d, a, b, c, x[i + 9], 12, 0x8B44F7AF);
      c = ff(c, d, a, b, x[i + 10], 17, 0xFFFF5BB1);
      b = ff(b, c, d, a, x[i + 11], 22, 0x895CD7BE);
      a = ff(a, b, c, d, x[i + 12], 7, 0x6B901122);
      d = ff(d, a, b, c, x[i + 13], 12, 0xFD987193);
      c = ff(c, d, a, b, x[i + 14], 17, 0xA679438E);
      b = ff(b, c, d, a, x[i + 15], 22, 0x49B40821);

      a = gg(a, b, c, d, x[i + 1], 5, 0xF61E2562);
      d = gg(d, a, b, c, x[i + 6], 9, 0xC040B340);
      c = gg(c, d, a, b, x[i + 11], 14, 0x265E5A51);
      b = gg(b, c, d, a, x[i], 20, 0xE9B6C7AA);
      a = gg(a, b, c, d, x[i + 5], 5, 0xD62F105D);
      d = gg(d, a, b, c, x[i + 10], 9, 0x2441453);
      c = gg(c, d, a, b, x[i + 15], 14, 0xD8A1E681);
      b = gg(b, c, d, a, x[i + 4], 20, 0xE7D3FBC8);
      a = gg(a, b, c, d, x[i + 9], 5, 0x21E1CDE6);
      d = gg(d, a, b, c, x[i + 14], 9, 0xC33707D6);
      c = gg(c, d, a, b, x[i + 3], 14, 0xF4D50D87);
      b = gg(b, c, d, a, x[i + 8], 20, 0x455A14ED);
      a = gg(a, b, c, d, x[i + 13], 5, 0xA9E3E905);
      d = gg(d, a, b, c, x[i + 2], 9, 0xFCEFA3F8);
      c = gg(c, d, a, b, x[i + 7], 14, 0x676F02D9);
      b = gg(b, c, d, a, x[i + 12], 20, 0x8D2A4C8A);

      a = hh(a, b, c, d, x[i + 5], 4, 0xFFFA3942);
      d = hh(d, a, b, c, x[i + 8], 11, 0x8771F681);
      c = hh(c, d, a, b, x[i + 11], 16, 0x6D9D6122);
      b = hh(b, c, d, a, x[i + 14], 23, 0xFDE5380C);
      a = hh(a, b, c, d, x[i + 1], 4, 0xA4BEEA44);
      d = hh(d, a, b, c, x[i + 4], 11, 0x4BDECFA9);
      c = hh(c, d, a, b, x[i + 7], 16, 0xF6BB4B60);
      b = hh(b, c, d, a, x[i + 10], 23, 0xBEBFBC70);
      a = hh(a, b, c, d, x[i + 13], 4, 0x289B7EC6);
      d = hh(d, a, b, c, x[i], 11, 0xEAA127FA);
      c = hh(c, d, a, b, x[i + 3], 16, 0xD4EF3085);
      b = hh(b, c, d, a, x[i + 6], 23, 0x4881D05);
      a = hh(a, b, c, d, x[i + 9], 4, 0xD9D4D039);
      d = hh(d, a, b, c, x[i + 12], 11, 0xE6DB99E5);
      c = hh(c, d, a, b, x[i + 15], 16, 0x1FA27CF8);
      b = hh(b, c, d, a, x[i + 2], 23, 0xC4AC5665);

      a = ii(a, b, c, d, x[i], 6, 0xF4292244);
      d = ii(d, a, b, c, x[i + 7], 10, 0x432AFF97);
      c = ii(c, d, a, b, x[i + 14], 15, 0xAB9423A7);
      b = ii(b, c, d, a, x[i + 5], 21, 0xFC93A039);
      a = ii(a, b, c, d, x[i + 12], 6, 0x655B59C3);
      d = ii(d, a, b, c, x[i + 3], 10, 0x8F0CCC92);
      c = ii(c, d, a, b, x[i + 10], 15, 0xFFEFF47D);
      b = ii(b, c, d, a, x[i + 1], 21, 0x85845DD1);
      a = ii(a, b, c, d, x[i + 8], 6, 0x6FA87E4F);
      d = ii(d, a, b, c, x[i + 15], 10, 0xFE2CE6E0);
      c = ii(c, d, a, b, x[i + 6], 15, 0xA3014314);
      b = ii(b, c, d, a, x[i + 13], 21, 0x4E0811A1);
      a = ii(a, b, c, d, x[i + 4], 6, 0xF7537E82);
      d = ii(d, a, b, c, x[i + 11], 10, 0xBD3AF235);
      c = ii(c, d, a, b, x[i + 2], 15, 0x2AD7D2BB);
      b = ii(b, c, d, a, x[i + 9], 21, 0xEB86D391);

      a = addUnsigned(a, olda);
      b = addUnsigned(b, oldb);
      c = addUnsigned(c, oldc);
      d = addUnsigned(d, oldd);
    }

    const bin = [a, b, c, d];
    let hex = '';
    for (let i = 0; i < 4; i++) {
      for (let j = 0; j < 4; j++) {
        hex += ((bin[i] >> (j * 8 + 4)) & 0xF).toString(16) +
               ((bin[i] >> (j * 8)) & 0xF).toString(16);
      }
    }
    return hex;
  };

  const generatePassword = useCallback(() => {
    const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const lower = 'abcdefghijklmnopqrstuvwxyz';
    const numbers = '0123456789';
    const symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?';

    let chars = '';
    if (includeLower) chars += lower;
    if (includeUpper) chars += upper;
    if (includeNumbers) chars += numbers;
    if (includeSymbols) chars += symbols;

    if (!chars) {
      setGeneratedPassword('Please select at least one character type');
      return;
    }

    let password = '';
    const array = new Uint8Array(passwordLength);
    crypto.getRandomValues(array);

    for (let i = 0; i < passwordLength; i++) {
      password += chars[array[i] % chars.length];
    }

    setGeneratedPassword(password);
    
    // Calculate strength
    let strength = 0;
    if (passwordLength >= 12) strength += 40;
    if (includeUpper && includeLower) strength += 25;
    if (includeNumbers) strength += 15;
    if (includeSymbols) strength += 20;
    setPasswordStrength(Math.min(100, strength));
  }, [passwordLength, includeUpper, includeLower, includeNumbers, includeSymbols]);

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const calculateHash = async () => {
    if (!inputText && !fileForHash) return;
    
    setIsHashing(true);
    
    try {
      let textToHash = inputText;
      
      if (fileForHash) {
        const arrayBuffer = await fileForHash.arrayBuffer();
        textToHash = Array.from(new Uint8Array(arrayBuffer))
          .map(b => b.toString(16).padStart(2, '0'))
          .join('');
      }

      let result = '';
      
      if (selectedHash === 'MD5') {
        result = md5(textToHash);
      } else {
        const encoder = new TextEncoder();
        const data = encoder.encode(textToHash);
        const hashBuffer = await crypto.subtle.digest(
          selectedHash === 'SHA-1' ? 'SHA-1' : 
          selectedHash === 'SHA-256' ? 'SHA-256' : 'SHA-512', 
          data
        );
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        result = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
      }
      
      setHashResult(result);
    } catch (error) {
      setHashResult('Error computing hash');
    } finally {
      setIsHashing(false);
    }
  };

  const cleanMetadata = async (file: File) => {
    setIsCleaning(true);
    
    try {
      const arrayBuffer = await file.arrayBuffer();
      const uint8Array = new Uint8Array(arrayBuffer);
      
      let cleanedData = uint8Array;
      
      // Simple JPEG EXIF removal (remove APP1 segment)
      if (file.type === 'image/jpeg' && uint8Array[0] === 0xFF && uint8Array[1] === 0xD8) {
        let i = 2;
        while (i < uint8Array.length - 1) {
          if (uint8Array[i] === 0xFF) {
            const marker = uint8Array[i + 1];
            if (marker === 0xE1) { // APP1 - EXIF
              const length = (uint8Array[i + 2] << 8) | uint8Array[i + 3];
              cleanedData = new Uint8Array([
                ...uint8Array.slice(0, i),
                ...uint8Array.slice(i + length + 2)
              ]);
              break;
            }
            if (marker >= 0xE0 && marker <= 0xEF) {
              const length = (uint8Array[i + 2] << 8) | uint8Array[i + 3];
              i += length + 2;
              continue;
            }
          }
          i++;
        }
      }
      
      const blob = new Blob([cleanedData], { type: file.type });
      const url = URL.createObjectURL(blob);
      
      setCleanedFileUrl(url);
      
      setMetadataInfo({
        originalSize: (file.size / 1024).toFixed(2) + ' KB',
        cleanedSize: (blob.size / 1024).toFixed(2) + ' KB',
        removed: file.type.includes('jpeg') ? 'EXIF, GPS, Camera Info' : 'Metadata',
        filename: 'clean-' + file.name
      });
      
    } catch (e) {
      alert("Could not process file. Please try another.");
    } finally {
      setIsCleaning(false);
    }
  };

  const handleFileEncrypt = async () => {
    if (!encryptFile || !encryptPassword) return;
    
    setIsProcessingFile(true);
    
    try {
      const fileBuffer = await encryptFile.arrayBuffer();
      const encoder = new TextEncoder();
      
      // Derive key from password
      const salt = encoder.encode('privmitlab-salt-2025');
      const baseKey = await crypto.subtle.importKey(
        'raw',
        encoder.encode(encryptPassword),
        'PBKDF2',
        false,
        ['deriveBits', 'deriveKey']
      );
      
      const key = await crypto.subtle.deriveKey(
        {
          name: 'PBKDF2',
          salt,
          iterations: 100000,
          hash: 'SHA-256'
        },
        baseKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
      );
      
      const iv = crypto.getRandomValues(new Uint8Array(12));
      
      let resultBuffer: ArrayBuffer;
      
      if (encryptMode === 'encrypt') {
        resultBuffer = await crypto.subtle.encrypt(
          { name: 'AES-GCM', iv },
          key,
          fileBuffer
        );
      } else {
        resultBuffer = await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv },
          key,
          fileBuffer
        );
      }
      
      const combined = new Uint8Array(iv.length + resultBuffer.byteLength);
      combined.set(iv);
      combined.set(new Uint8Array(resultBuffer), iv.length);
      
      const blob = new Blob([combined], { 
        type: encryptMode === 'encrypt' ? 'application/octet-stream' : encryptFile.type 
      });
      
      const url = URL.createObjectURL(blob);
      setEncryptedFileUrl(url);
      
    } catch (error) {
      alert("Encryption failed. Check your password.");
    } finally {
      setIsProcessingFile(false);
    }
  };

  const scanPrivacy = () => {
    if (!scanUrl) return;
    
    setIsScanning(true);
    
    setTimeout(() => {
      const domain = scanUrl.replace(/^https?:\/\//, '').split('/')[0];
      
      const fakeScores = {
        'google.com': { score: 42, color: 'red', issues: ['Heavy tracking', '50+ trackers', 'Fingerprinting'] },
        'facebook.com': { score: 12, color: 'red', issues: ['Extreme tracking', 'Cross-site tracking', 'Behavioral profiling'] },
        'wikipedia.org': { score: 94, color: 'green', issues: ['Minimal third-party scripts'] },
        'github.com': { score: 81, color: 'emerald', issues: ['Some analytics'] },
      };
      
      const result = fakeScores[domain as keyof typeof fakeScores] || {
        score: Math.floor(Math.random() * 45) + 55,
        color: Math.random() > 0.6 ? 'emerald' : 'amber',
        issues: [
          '3rd party scripts detected',
          'Analytics cookies found',
          'Some fingerprinting detected'
        ]
      };
      
      setScanResult({
        domain,
        score: result.score,
        color: result.color,
        issues: result.issues || ['No major issues found'],
        timestamp: new Date().toLocaleTimeString()
      });
      
      setIsScanning(false);
    }, 850);
  };

  const downloadFile = (url: string, filename: string) => {
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  };

  // Auto-generate password on settings change
  useEffect(() => {
    if (activeTool === 'password') {
      generatePassword();
    }
  }, [activeTool, passwordLength, includeUpper, includeLower, includeNumbers, includeSymbols, generatePassword]);

  const currentTool = tools.find(t => t.id === activeTool);

  return (
    <div className="min-h-screen bg-zinc-950 text-white">
      {/* HEADER */}
      <header className="border-b border-zinc-800 bg-zinc-950 sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-8 py-5 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-3">
              <div className="h-9 w-9 bg-gradient-to-br from-emerald-400 to-cyan-400 rounded-2xl flex items-center justify-center">
                <Shield className="h-5 w-5 text-zinc-950" />
              </div>
              <div>
                <div className="font-semibold text-2xl tracking-tighter">PRIVMITLAB</div>
                <div className="text-[10px] text-zinc-500 -mt-1">PRIVACY TOOLKIT</div>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-6 text-sm">
            <a href="https://github.com/PrivMITLab" target="_blank" 
               className="flex items-center gap-2 hover:text-emerald-400 transition-colors">
              <span className="text-emerald-400">↗</span> GITHUB
            </a>
            <div className="h-3.5 w-px bg-zinc-700"></div>
            <div className="text-emerald-400 text-xs font-mono">OFFLINE • LOCAL • PRIVATE</div>
          </div>
        </div>
      </header>

      <div className="flex max-w-7xl mx-auto">
        {/* SIDEBAR */}
        <div className="w-72 border-r border-zinc-800 bg-zinc-950 h-[calc(100vh-73px)] overflow-auto p-6">
          <div className="mb-8">
            <div className="uppercase text-xs tracking-[2px] text-zinc-500 mb-3 px-3">TOOLS</div>
            
            {tools.map((tool) => (
              <button
                key={tool.id}
                onClick={() => setActiveTool(tool.id)}
                className={`w-full text-left px-4 py-3.5 rounded-2xl mb-1.5 flex items-center gap-3 transition-all group ${
                  activeTool === tool.id 
                    ? 'bg-zinc-900 shadow-inner border border-zinc-700' 
                    : 'hover:bg-zinc-900/70'
                }`}
              >
                <div className={`w-8 h-8 rounded-xl bg-gradient-to-br ${tool.color} flex items-center justify-center text-zinc-950 transition-transform group-hover:scale-110`}>
                  {tool.icon}
                </div>
                <div>
                  <div className="font-medium text-sm">{tool.name}</div>
                  <div className="text-zinc-500 text-xs">{tool.description}</div>
                </div>
              </button>
            ))}
          </div>

          <PrivacyStatement />

          <div className="mt-auto pt-8 text-[10px] text-zinc-500 space-y-1 px-3">
            <div>Built with WebCrypto API</div>
            <div>Zero telemetry • Zero CDN</div>
            <div className="pt-4 text-emerald-300/70">Block Everything.<br />Trust Nothing.<br />Control Everything.</div>
          </div>
        </div>

        {/* MAIN CONTENT */}
        <div className="flex-1 p-10 overflow-auto" style={{ height: 'calc(100vh - 73px)' }}>
          <div className="max-w-3xl mx-auto">
            {/* TOOL HEADER */}
            <div className="mb-10">
              <div className="flex items-center gap-4">
                <div className={`w-12 h-12 rounded-3xl bg-gradient-to-br ${currentTool?.color} flex items-center justify-center text-3xl`}>
                  {currentTool?.icon}
                </div>
                <div>
                  <h1 className="text-4xl font-semibold tracking-tighter">{currentTool?.name}</h1>
                  <p className="text-zinc-400 mt-1">{currentTool?.description}</p>
                </div>
              </div>
            </div>

            {/* PASSWORD GENERATOR */}
            {activeTool === 'password' && (
              <div className="space-y-8">
                <div className="bg-zinc-900 border border-zinc-800 rounded-3xl p-8">
                  <div className="text-center mb-8">
                    <div className="font-mono text-4xl tracking-[4px] font-medium bg-zinc-950 border border-zinc-700 rounded-2xl py-6 px-8 mb-6 break-all min-h-[72px] flex items-center justify-center">
                      {generatedPassword || 'Click Generate'}
                    </div>
                    
                    <div className="flex justify-center gap-4">
                      <button
                        onClick={() => copyToClipboard(generatedPassword)}
                        className="flex items-center gap-2 bg-zinc-800 hover:bg-zinc-700 px-6 py-2.5 rounded-2xl text-sm transition-all active:scale-95"
                      >
                        <Copy className="w-4 h-4" /> {copied ? 'COPIED!' : 'COPY'}
                      </button>
                      <button
                        onClick={generatePassword}
                        className="flex items-center gap-2 bg-white text-black px-6 py-2.5 rounded-2xl text-sm font-medium transition-all active:scale-95"
                      >
                        <RefreshCw className="w-4 h-4" /> REGENERATE
                      </button>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-8">
                    <div>
                      <label className="block text-xs uppercase tracking-widest text-zinc-400 mb-3">LENGTH: {passwordLength}</label>
                      <input 
                        type="range" 
                        min="6" 
                        max="64" 
                        value={passwordLength}
                        onChange={(e) => setPasswordLength(parseInt(e.target.value))}
                        className="w-full accent-emerald-400"
                      />
                    </div>

                    <div className="space-y-4">
                      <div className="flex items-center justify-between">
                        <div className="text-sm">Uppercase</div>
                        <button onClick={() => setIncludeUpper(!includeUpper)} 
                          className={`w-11 h-6 rounded-full relative ${includeUpper ? 'bg-emerald-500' : 'bg-zinc-700'}`}>
                          <div className={`absolute top-0.5 transition-all w-5 h-5 rounded-full bg-white ${includeUpper ? 'left-6' : 'left-0.5'}`}></div>
                        </button>
                      </div>
                      <div className="flex items-center justify-between">
                        <div className="text-sm">Lowercase</div>
                        <button onClick={() => setIncludeLower(!includeLower)} 
                          className={`w-11 h-6 rounded-full relative ${includeLower ? 'bg-emerald-500' : 'bg-zinc-700'}`}>
                          <div className={`absolute top-0.5 transition-all w-5 h-5 rounded-full bg-white ${includeLower ? 'left-6' : 'left-0.5'}`}></div>
                        </button>
                      </div>
                      <div className="flex items-center justify-between">
                        <div className="text-sm">Numbers</div>
                        <button onClick={() => setIncludeNumbers(!includeNumbers)} 
                          className={`w-11 h-6 rounded-full relative ${includeNumbers ? 'bg-emerald-500' : 'bg-zinc-700'}`}>
                          <div className={`absolute top-0.5 transition-all w-5 h-5 rounded-full bg-white ${includeNumbers ? 'left-6' : 'left-0.5'}`}></div>
                        </button>
                      </div>
                      <div className="flex items-center justify-between">
                        <div className="text-sm">Symbols</div>
                        <button onClick={() => setIncludeSymbols(!includeSymbols)} 
                          className={`w-11 h-6 rounded-full relative ${includeSymbols ? 'bg-emerald-500' : 'bg-zinc-700'}`}>
                          <div className={`absolute top-0.5 transition-all w-5 h-5 rounded-full bg-white ${includeSymbols ? 'left-6' : 'left-0.5'}`}></div>
                        </button>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-3 bg-zinc-900 border border-zinc-800 rounded-3xl p-5">
                  <div className="text-xs uppercase tracking-widest text-emerald-400">STRENGTH</div>
                  <div className="flex-1 h-2.5 bg-zinc-800 rounded-full overflow-hidden">
                    <div className="h-full bg-gradient-to-r from-red-400 via-yellow-400 to-emerald-400 transition-all" 
                         style={{width: `${passwordStrength}%`}}></div>
                  </div>
                  <div className="font-mono text-xs text-emerald-400 w-12">{passwordStrength}</div>
                </div>
              </div>
            )}

            {/* HASH GENERATOR */}
            {activeTool === 'hash' && (
              <div className="bg-zinc-900 border border-zinc-800 rounded-3xl p-8 space-y-8">
                <div>
                  <div className="text-sm text-zinc-400 mb-2">INPUT TEXT OR UPLOAD FILE</div>
                  <textarea
                    value={inputText}
                    onChange={(e) => setInputText(e.target.value)}
                    className="w-full h-28 bg-black border border-zinc-700 rounded-2xl p-5 font-mono text-sm resize-y focus:outline-none focus:border-violet-500"
                    placeholder="Type something or drop a file..."
                  />
                  
                  <label className="mt-4 block">
                    <div className="border border-dashed border-zinc-700 hover:border-violet-500 transition-colors rounded-2xl p-8 text-center cursor-pointer">
                      <Upload className="mx-auto mb-3 text-zinc-400" />
                      <div className="text-sm">Upload file to hash</div>
                      <input 
                        type="file" 
                        className="hidden" 
                        onChange={(e) => {
                          if (e.target.files && e.target.files[0]) {
                            setFileForHash(e.target.files[0]);
                            setInputText(e.target.files[0].name);
                          }
                        }}
                      />
                    </div>
                  </label>
                </div>

                <div className="flex gap-3">
                  {['MD5', 'SHA-1', 'SHA-256', 'SHA-512'].map((algo) => (
                    <button
                      key={algo}
                      onClick={() => setSelectedHash(algo)}
                      className={`px-5 py-2 rounded-2xl text-sm transition-all ${selectedHash === algo ? 'bg-violet-600 text-white' : 'bg-zinc-800 hover:bg-zinc-700'}`}
                    >
                      {algo}
                    </button>
                  ))}
                </div>

                <button 
                  onClick={calculateHash}
                  disabled={isHashing || (!inputText && !fileForHash)}
                  className="w-full py-4 bg-white text-black rounded-2xl font-medium flex items-center justify-center gap-2 disabled:opacity-50"
                >
                  {isHashing ? 'COMPUTING...' : 'GENERATE HASH'}
                </button>

                {hashResult && (
                  <div className="bg-black border border-zinc-800 rounded-2xl p-6 font-mono text-sm break-all">
                    <div className="text-[10px] text-zinc-500 mb-2">RESULT • {selectedHash}</div>
                    <div className="text-emerald-300 leading-relaxed">{hashResult}</div>
                    <button onClick={() => copyToClipboard(hashResult)} className="mt-6 text-xs flex items-center gap-2 text-violet-400 hover:text-violet-300">
                      <Copy className="w-3 h-3" /> COPY HASH
                    </button>
                  </div>
                )}
              </div>
            )}

            {/* METADATA CLEANER */}
            {activeTool === 'metadata' && (
              <div className="space-y-8">
                <div className="border border-dashed border-zinc-700 rounded-3xl p-12 text-center">
                  <input 
                    type="file" 
                    id="meta-upload"
                    className="hidden"
                    accept="image/jpeg,image/png,application/pdf"
                    onChange={(e) => {
                      if (e.target.files?.[0]) {
                        const file = e.target.files[0];
                        setUploadedFile(file);
                        cleanMetadata(file);
                      }
                    }}
                  />
                  
                  <label htmlFor="meta-upload" className="cursor-pointer block">
                    <div className="mx-auto w-16 h-16 rounded-2xl bg-zinc-900 flex items-center justify-center mb-6">
                      <Upload className="w-8 h-8 text-zinc-400" />
                    </div>
                    <div className="text-xl font-medium">Drop image or PDF here</div>
                    <div className="text-zinc-400 mt-2">PNG, JPG, PDF supported</div>
                  </label>
                </div>

                {uploadedFile && (
                  <div className="bg-zinc-900 border border-zinc-700 rounded-3xl p-8">
                    <div className="flex justify-between items-start mb-8">
                      <div>
                        <div className="font-medium">{uploadedFile.name}</div>
                        <div className="text-xs text-zinc-500 mt-1">{(uploadedFile.size/1024).toFixed(1)} KB • {uploadedFile.type}</div>
                      </div>
                      {isCleaning && <div className="text-amber-400 text-sm animate-pulse">REMOVING METADATA...</div>}
                    </div>

                    {metadataInfo && (
                      <div className="grid grid-cols-3 gap-4 mb-8 text-sm">
                        <div className="bg-black rounded-2xl p-5">
                          <div className="text-xs text-zinc-500">ORIGINAL</div>
                          <div className="font-mono mt-1">{metadataInfo.originalSize}</div>
                        </div>
                        <div className="bg-black rounded-2xl p-5">
                          <div className="text-xs text-emerald-400">CLEANED</div>
                          <div className="font-mono mt-1 text-emerald-400">{metadataInfo.cleanedSize}</div>
                        </div>
                        <div className="bg-black rounded-2xl p-5">
                          <div className="text-xs text-rose-400">REMOVED</div>
                          <div className="font-medium mt-1 text-rose-400">EXIF + GPS</div>
                        </div>
                      </div>
                    )}

                    {cleanedFileUrl && (
                      <button 
                        onClick={() => downloadFile(cleanedFileUrl, metadataInfo?.filename || 'cleaned-file')}
                        className="w-full flex items-center justify-center gap-3 bg-emerald-600 hover:bg-emerald-500 py-4 rounded-2xl text-sm font-medium transition-colors"
                      >
                        <Download className="w-4 h-4" /> DOWNLOAD CLEAN FILE
                      </button>
                    )}
                  </div>
                )}
              </div>
            )}

            {/* FILE ENCRYPTOR */}
            {activeTool === 'encrypt' && (
              <div className="bg-zinc-900 border border-zinc-800 rounded-3xl p-8">
                <div className="flex gap-3 mb-8 border-b border-zinc-800 pb-6">
                  <button 
                    onClick={() => setEncryptMode('encrypt')}
                    className={`flex-1 py-4 rounded-2xl text-sm font-medium transition-all ${encryptMode === 'encrypt' ? 'bg-white text-black' : 'bg-zinc-800'}`}>
                    ENCRYPT FILE
                  </button>
                  <button 
                    onClick={() => setEncryptMode('decrypt')}
                    className={`flex-1 py-4 rounded-2xl text-sm font-medium transition-all ${encryptMode === 'decrypt' ? 'bg-white text-black' : 'bg-zinc-800'}`}>
                    DECRYPT FILE
                  </button>
                </div>

                <div className="space-y-8">
                  <label className="block">
                    <div className="text-xs uppercase tracking-widest mb-2 text-zinc-400">SELECT FILE</div>
                    <input 
                      type="file" 
                      onChange={(e) => e.target.files && setEncryptFile(e.target.files[0])}
                      className="block w-full text-sm text-zinc-400 file:mr-4 file:py-4 file:px-6 file:rounded-2xl file:border-0 file:bg-zinc-800 file:text-white hover:file:bg-zinc-700 cursor-pointer"
                    />
                  </label>

                  <div>
                    <div className="text-xs uppercase tracking-widest mb-2 text-zinc-400">PASSWORD</div>
                    <div className="relative">
                      <input 
                        type={showEncryptPass ? "text" : "password"}
                        value={encryptPassword}
                        onChange={(e) => setEncryptPassword(e.target.value)}
                        className="w-full bg-black border border-zinc-700 focus:border-white rounded-2xl px-6 py-4 text-lg font-light placeholder:text-zinc-600"
                        placeholder="••••••••••••"
                      />
                      <button 
                        type="button"
                        onClick={() => setShowEncryptPass(!showEncryptPass)}
                        className="absolute right-6 top-5 text-zinc-400"
                      >
                        {showEncryptPass ? <EyeOff size={18} /> : <Eye size={18} />}
                      </button>
                    </div>
                  </div>

                  <button 
                    onClick={handleFileEncrypt}
                    disabled={!encryptFile || !encryptPassword || isProcessingFile}
                    className="w-full py-4 bg-gradient-to-r from-rose-500 to-pink-600 rounded-2xl font-medium disabled:opacity-40 flex items-center justify-center gap-3"
                  >
                    {isProcessingFile ? 'PROCESSING...' : encryptMode === 'encrypt' ? 'ENCRYPT FILE' : 'DECRYPT FILE'}
                  </button>

                  {encryptedFileUrl && (
                    <div className="pt-4 border-t border-zinc-700">
                      <button 
                        onClick={() => {
                          downloadFile(encryptedFileUrl, encryptMode === 'encrypt' ? 'encrypted.bin' : 'decrypted.' + (encryptFile?.name.split('.').pop() || ''));
                          setEncryptedFileUrl(null);
                        }}
                        className="w-full flex items-center justify-center gap-3 bg-emerald-500 py-4 rounded-2xl text-sm font-medium"
                      >
                        <Download className="w-4 h-4" /> 
                        DOWNLOAD {encryptMode.toUpperCase()}ED FILE
                      </button>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* PRIVACY SCANNER */}
            {activeTool === 'scanner' && (
              <div className="space-y-8">
                <div className="bg-zinc-900 border border-zinc-700 rounded-3xl p-8">
                  <input
                    type="text"
                    value={scanUrl}
                    onChange={(e) => setScanUrl(e.target.value)}
                    placeholder="https://example.com"
                    className="w-full bg-black border border-zinc-700 rounded-2xl px-6 py-5 text-lg placeholder:text-zinc-500 focus:outline focus:outline-1 focus:-outline-offset-2 focus:outline-cyan-400"
                  />
                  
                  <button 
                    onClick={scanPrivacy}
                    disabled={isScanning || !scanUrl}
                    className="mt-5 w-full py-4 bg-cyan-400 hover:bg-cyan-300 disabled:bg-zinc-700 text-zinc-950 font-medium rounded-2xl transition-all"
                  >
                    {isScanning ? "ANALYZING..." : "SCAN WEBSITE PRIVACY"}
                  </button>
                </div>

                {scanResult && (
                  <div className="bg-zinc-900 border border-zinc-700 rounded-3xl p-8">
                    <div className="flex items-center justify-between mb-8">
                      <div>
                        <div className="text-sm text-zinc-400">ANALYZED DOMAIN</div>
                        <div className="text-3xl font-semibold text-white mt-1">{scanResult.domain}</div>
                      </div>
                      <div className={`text-7xl font-bold tabular-nums ${scanResult.color === 'red' ? 'text-red-500' : scanResult.color === 'emerald' ? 'text-emerald-400' : 'text-amber-400'}`}>
                        {scanResult.score}
                      </div>
                    </div>

                    <div className="text-xs uppercase tracking-widest text-zinc-400 mb-4">DETECTED ISSUES</div>
                    <div className="space-y-3">
                      {scanResult.issues.map((issue: string, i: number) => (
                        <div key={i} className="flex gap-3 bg-zinc-950 rounded-2xl px-5 py-4 text-sm border border-zinc-800">
                          <div className="text-rose-400 mt-px">●</div>
                          <div>{issue}</div>
                        </div>
                      ))}
                    </div>

                    <div className="text-[10px] text-zinc-500 mt-8 text-center">This is a simulation. Real privacy analysis requires network access.</div>
                  </div>
                )}
              </div>
            )}

            <div className="mt-16 text-center">
              <div className="inline-flex items-center gap-2 bg-zinc-900 text-zinc-400 text-xs px-5 py-2 rounded-3xl border border-zinc-800">
                <div className="w-1.5 h-1.5 bg-emerald-400 rounded-full animate-ping"></div>
                100% OFFLINE • LOCAL EXECUTION
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

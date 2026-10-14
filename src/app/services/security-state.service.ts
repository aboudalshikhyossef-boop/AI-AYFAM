import { Injectable, signal, computed } from '@angular/core';
import {
  Finding,
  UsbDevice,
  AuditEvent,
  Playbook,
  ThreatIntelItem,
  KnowledgeDoc,
  SystemTelemetry,
  ChatMessage,
  Severity,
} from '../models/security.model';
import { AiAssistantService } from './ai-assistant.service';

interface ScanResponse {
  ok: boolean;
  findings: Finding[];
  profile: string;
  source: string;
  elapsedMs: number;
  counts: Record<string, number>;
}

@Injectable({
  providedIn: 'root',
})
export class SecurityStateService {
  private readonly assistant = new AiAssistantService();
  // Locale State: 'ar' | 'en'
  readonly locale = signal<'ar' | 'en'>('ar');
  readonly currentView = signal<string>('dashboard');

  // Live Telemetry
  readonly telemetry = signal<SystemTelemetry>({
    cpuUsage: 14,
    memoryUsage: 42,
    diskUsage: 38,
    activeSockets: 68,
    openPorts: [22, 80, 443, 631, 8080],
    securityScore: 68,
    status: 'idle',
    lastAuditTime: '2026-10-10 10:04:12',
    hostname: 'ayfam-mint-srv01',
    kernelVersion: 'Linux 6.8.0-45-generic #45-Ubuntu',
    osRelease: 'Linux Mint 22 (Wilma) x86_64',
  });

  // Discovered Security Findings
  readonly findings = signal<Finding[]>([
    {
      id: 'f-ssh-01',
      severity: 'critical',
      title: 'تسجيل دخول Root مفعل عبر بروتوكول SSH',
      titleEn: 'PermitRootLogin Enabled in SSH Daemon Configuration',
      detail: 'ملف /etc/ssh/sshd_config يحتوي على "PermitRootLogin yes"، مما يعرض الخادم لهجمات التخمين المباشرة كمدير نظام.',
      detailEn: '/etc/ssh/sshd_config permits direct root login, allowing attackers to perform automated brute-force attacks directly as superuser.',
      fix: "sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && systemctl reload sshd",
      fixEn: "Set PermitRootLogin no in /etc/ssh/sshd_config and reload SSH daemon.",
      category: 'ssh_hardening',
      tags: ['ssh', 'bruteforce', 'cis-benchmark'],
      attackIds: ['T1078.003', 'T1110.001'],
      effort: 'low',
      riskOfFix: 'low',
      fixed: false,
      discoveredAt: '10:02:15',
    },
    {
      id: 'f-ufw-02',
      severity: 'high',
      title: 'جدار الحماية UFW معطل على الواجهة الخارجية',
      titleEn: 'UFW Firewall Inactive on Network Interfaces',
      detail: 'خدمة ufw غير مفعلة، مما يترك المنافذ 8080 و 631 مفتوحة ومعرضة للاتصالات الخارجية العشوائية.',
      detailEn: 'Uncomplicated Firewall (UFW) is currently disabled, exposing open internal ports (8080, 631) to potential external probes.',
      fix: 'ufw default deny incoming && ufw default allow outgoing && ufw allow 22/tcp && ufw allow 443/tcp && ufw --force enable',
      fixEn: 'Configure default deny policy and enable UFW with authorized service ports.',
      category: 'firewall',
      tags: ['network', 'perimeter', 'ufw'],
      attackIds: ['T1046', 'T1190'],
      effort: 'low',
      riskOfFix: 'medium',
      fixed: false,
      discoveredAt: '10:02:18',
    },
    {
      id: 'f-suid-03',
      severity: 'high',
      title: 'ملف تنفيذي غير قياسي يحمل صلاحيات SUID (مسار غير معتاد)',
      titleEn: 'Unusual SUID Binary Detected in /usr/local/bin',
      detail: 'تم العثور على /usr/local/bin/backup_exec يحمل البت +s ومملوك لـ root، ويمكن استغلاله لتصعيد الصلاحيات محلياً (GTFOBins).',
      detailEn: '/usr/local/bin/backup_exec has SUID permission bit set owned by root. Can be leveraged for local privilege escalation.',
      fix: 'chmod u-s /usr/local/bin/backup_exec',
      fixEn: 'Remove SUID bit from non-standard binary.',
      category: 'suid_privesc',
      tags: ['suid', 'privesc', 'gtfobins'],
      attackIds: ['T1548.001'],
      effort: 'low',
      riskOfFix: 'low',
      fixed: false,
      discoveredAt: '10:02:22',
    },
    {
      id: 'f-sec-04',
      severity: 'medium',
      title: 'تسريب محتمل لمفتاح API في سجل أوامر Bash',
      titleEn: 'Potential API Token Leaked in Shell History (.bash_history)',
      detail: 'رصد نمط مفتاح سري "ghp_xxxxxxxxxxxx" في سطر 412 من /root/.bash_history.',
      detailEn: 'Detected GitHub personal access token signature in /root/.bash_history line 412.',
      fix: 'history -c && truncate -s 0 ~/.bash_history && sed -i \'/ghp_/d\' ~/.bash_history',
      fixEn: 'Purge credential string from shell history file and rotate token on provider.',
      category: 'secret_leak',
      tags: ['leak', 'credentials', 'token'],
      attackIds: ['T1552.003'],
      effort: 'low',
      riskOfFix: 'low',
      fixed: false,
      discoveredAt: '10:02:29',
    },
    {
      id: 'f-port-05',
      severity: 'medium',
      title: 'منفذ تصحيح أخطاء عام 8080 غير محمي بتوثيق',
      titleEn: 'Debug Proxy Port 8080 Listening on 0.0.0.0 without TLS',
      detail: 'خادم Node/Java يستمع على جميع الواجهات 0.0.0.0:8080 بدون طبقة تشفير TLS أو تحكم بالوصول.',
      detailEn: 'Service listening on all network interfaces 0.0.0.0:8080 without encryption or ACL restrictions.',
      fix: 'iptables -A INPUT -p tcp --dport 8080 -s 127.0.0.1 -j ACCEPT && iptables -A INPUT -p tcp --dport 8080 -j DROP',
      fixEn: 'Bind service to localhost or restrict access via iptables/firewall rule.',
      category: 'network_audit',
      tags: ['ports', 'cleartext', 'exposure'],
      attackIds: ['T1040'],
      effort: 'medium',
      riskOfFix: 'medium',
      fixed: false,
      discoveredAt: '10:02:35',
    },
    {
      id: 'f-pass-06',
      severity: 'low',
      title: 'صلاحيات ملف /etc/shadow غير مطابقة لمعايير CIS',
      titleEn: 'File Permissions on /etc/shadow Overly Permissive',
      detail: 'الصلاحيات الحالية هي 0644، والمطلوب وفق CIS Benchmark هو 0640 أو 0000 فقط لـ root/shadow.',
      detailEn: 'Current file permissions on /etc/shadow are wider than CIS Benchmark baseline (0640 or stricter).',
      fix: 'chmod 0640 /etc/shadow && chown root:shadow /etc/shadow',
      fixEn: 'Restrict /etc/shadow permissions to 0640 root:shadow.',
      category: 'cis_hardening',
      tags: ['permissions', 'cis', 'shadow'],
      attackIds: ['T1003.008'],
      effort: 'low',
      riskOfFix: 'low',
      fixed: false,
      discoveredAt: '10:02:40',
    },
  ]);

  // USB Devices Inventory
  readonly usbDevices = signal<UsbDevice[]>([
    {
      id: 'usb-01',
      vendorId: '0951',
      productId: '1666',
      name: 'Kingston DataTraveler 3.0',
      nameEn: 'Kingston DataTraveler 3.0 (Storage)',
      deviceType: 'Storage',
      busNumber: 'Bus 002 Device 004',
      authorized: true,
      mountPoint: '/media/usb_storage0',
      badUsbRisk: 'low',
      heuristics: ['Partitions: FAT32', 'No hidden autorun.inf', 'Signed firmware signature'],
    },
    {
      id: 'usb-02',
      vendorId: '1b1c',
      productId: '1b49',
      name: 'Corsair Gaming K55 Keyboard',
      nameEn: 'Corsair Gaming K55 Keyboard (HID)',
      deviceType: 'HID',
      busNumber: 'Bus 001 Device 003',
      authorized: true,
      badUsbRisk: 'low',
      heuristics: ['Standard USB HID report descriptor', 'Keystroke timing normal'],
    },
    {
      id: 'usb-03',
      vendorId: '2e8a',
      productId: '0005',
      name: 'Raspberry Pi Pico (BadUSB Payload Risk)',
      nameEn: 'Raspberry Pi Pico / Microcontroller (Emulating Keyboard)',
      deviceType: 'HID',
      busNumber: 'Bus 001 Device 007',
      authorized: false,
      badUsbRisk: 'high',
      heuristics: [
        'Device presents as HID keyboard without physical keyboard vendor ID',
        'Burst injection rate: >180 WPM simulated keystrokes',
        'Suspicious PowerShell / Bash reverse-shell stager signature detected',
      ],
    },
    {
      id: 'usb-04',
      vendorId: '04e8',
      productId: '6860',
      name: 'Samsung Galaxy A-Series (MTP/ADB)',
      nameEn: 'Samsung Galaxy Android (MTP Device)',
      deviceType: 'Phone',
      busNumber: 'Bus 003 Device 002',
      authorized: false,
      badUsbRisk: 'medium',
      heuristics: ['ADB debugging channel active', 'Unrestricted mass storage access requested'],
    },
  ]);

  // Live Audit Events Log Feed
  readonly auditEvents = signal<AuditEvent[]>([
    {
      id: 'e-1',
      timestamp: '10:00:02',
      level: 'INFO',
      message: 'بدء تشغيل محرك AI AYFAM v6 — تحميل قواعد الفحص والتصنيف المحلي',
      messageEn: 'AI AYFAM v6 engine initialized — local rule sets and taxonomy loaded',
      category: 'engine',
    },
    {
      id: 'e-2',
      timestamp: '10:00:15',
      level: 'INFO',
      message: 'فحص التوافق مع Linux Mint 22 — معمارية x86_64 — النواة 6.8.0',
      messageEn: 'Compatibility check passed for Linux Mint 22 — x86_64 — Kernel 6.8.0',
      category: 'preflight',
    },
    {
      id: 'e-3',
      timestamp: '10:02:15',
      level: 'CRIT',
      message: 'تحذير أمني حرج: SSH PermitRootLogin مفعل على المنفذ 22',
      messageEn: 'CRITICAL Security Alert: SSH PermitRootLogin enabled on port 22',
      category: 'ssh',
    },
    {
      id: 'e-4',
      timestamp: '10:02:18',
      level: 'WARN',
      message: 'تحذير جدار الحماية: UFW غير نشط، والمنافذ مكشوفة للخارج',
      messageEn: 'Firewall Alert: UFW inactive, listening services publicly exposed',
      category: 'firewall',
    },
    {
      id: 'e-5',
      timestamp: '10:02:22',
      level: 'WARN',
      message: 'رصد ملف SUID مريب: /usr/local/bin/backup_exec مع صلاحية root',
      messageEn: 'Suspicious SUID binary detected: /usr/local/bin/backup_exec (GTFOBins pattern)',
      category: 'suid',
    },
    {
      id: 'e-6',
      timestamp: '10:03:05',
      level: 'CRIT',
      message: 'رصد جهاز USB غير مصرح به: وحدة Raspberry Pi Pico تحاكي لوحة مفاتيح HID',
      messageEn: 'Unauthorized USB connected: Raspberry Pi Pico emulating HID keyboard (BadUSB risk)',
      category: 'usb',
    },
  ]);

  // Incident Response Playbooks
  readonly playbooks = signal<Playbook[]>([
    {
      id: 'pb-ransomware',
      title: 'خطة احتواء فيروسات الفدية والتشفير (Ransomware Containment)',
      titleEn: 'Ransomware Incident Containment Playbook',
      description: 'إجراءات فورية لعزل الخادم، إيقاف عمليات التشفير المشبوهة، وحماية النسخ الاحتياطية.',
      descriptionEn: 'Immediate containment procedures to isolate host, freeze suspect encryption processes, and preserve backups.',
      category: 'incident_response',
      mitreRef: 'T1486 (Data Encrypted for Impact)',
      steps: [
        {
          stepId: 1,
          title: 'عزل الخادم عن الشبكة فوراً',
          titleEn: 'Isolate host from local network',
          command: 'ip link set dev eth0 down && ufw default deny outgoing',
          description: 'قطع الاتصال لمنع انتشار برمجيات الفدية عبر SMB/NFS للأجهزة الأخرى.',
          descriptionEn: 'Disconnect network adapters to prevent lateral movement across subnets.',
          completed: false,
          automated: true,
        },
        {
          stepId: 2,
          title: 'تجميد العمليات المشبوهة ذات الاستهلاك العالي للقرص',
          titleEn: 'Freeze high I/O suspicious processes',
          command: 'killall -STOP suspect_proc || pkill -SIGSTOP -f encrypt',
          description: 'إرسال إشارة SIGSTOP لتجميد العمليات دون إنهاء الذاكرة لحفظ الأدلة الجنائية.',
          descriptionEn: 'Send SIGSTOP signal to freeze encryption threads while preserving volatile memory.',
          completed: false,
          automated: true,
        },
        {
          stepId: 3,
          title: 'حماية وتأمين النسخ الاحتياطية المحلية ومجلدات التخزين',
          titleEn: 'Make backup storage mounts read-only',
          command: 'mount -o remount,ro /mnt/backups',
          description: 'إعادة تركيب أقراص النسخ الاحتياطية بوضع القراءة فقط لمنع تشفيرها.',
          descriptionEn: 'Remount backup volumes as read-only to prevent tampering.',
          completed: false,
          automated: true,
        },
        {
          stepId: 4,
          title: 'أخذ لقطة من الذاكرة الحية (RAM Forensics Dump)',
          titleEn: 'Dump volatile system RAM for forensic key recovery',
          command: 'dd if=/dev/fmem of=/var/log/forensics_ram.raw bs=1M count=2048',
          description: 'استخراج مفاتيح التشفير المحتملة من الذاكرة قبل إيقاف تشغيل الخادم.',
          descriptionEn: 'Capture memory dump to extract candidate encryption keys and C2 sockets.',
          completed: false,
          automated: false,
        },
      ],
    },
    {
      id: 'pb-ssh-bruteforce',
      title: 'خطة صد هجمات التخمين والاختراق لخدمة SSH',
      titleEn: 'SSH Brute-Force & Credential Stuffing Remediation',
      description: 'حظر عناوين IP المهاجمة وتفعيل الحماية التلقائية بواسطة Fail2Ban وشهادات Ed25519.',
      descriptionEn: 'Block attacking IPs, enforce SSH key authentication, and deploy automated Fail2Ban jails.',
      category: 'hardening',
      mitreRef: 'T1110 (Brute Force)',
      steps: [
        {
          stepId: 1,
          title: 'تفعيل جدار الحماية وحظر تسجيل دخول Root',
          titleEn: 'Disable root SSH login and apply baseline ACL',
          command: "sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && systemctl reload sshd",
          description: 'منع محاولات الدخول بصلاحية المدير مباشرة.',
          descriptionEn: 'Enforce non-root SSH authentication.',
          completed: true,
          automated: true,
        },
        {
          stepId: 2,
          title: 'تعطيل توثيق كلمات المرور والاعتماد على مفاتيح SSH فقط',
          titleEn: 'Enforce Public Key Authentication only',
          command: "sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && systemctl reload sshd",
          description: 'إلغاء التوثيق النصي وحصره بالمفاتيح المشفرة فقط.',
          descriptionEn: 'Disable plaintext password authentication in sshd config.',
          completed: false,
          automated: true,
        },
        {
          stepId: 3,
          title: 'تثبيت وتفعيل سجن Fail2Ban لمراقبة محاولات الدخول الفاشلة',
          titleEn: 'Deploy Fail2ban SSH jail',
          command: 'apt-get install -y fail2ban && systemctl enable --now fail2ban',
          description: 'حظر أي IP يتجاوز 3 محاولات فاشلة تلقائياً لمدة 24 ساعة.',
          descriptionEn: 'Automatically ban malicious IP addresses after 3 failed login attempts.',
          completed: false,
          automated: true,
        },
      ],
    },
    {
      id: 'pb-badusb',
      title: 'خطة عزل أجهزة BadUSB والتسريب المادي',
      titleEn: 'BadUSB & Physical Device Exfiltration Containment',
      description: 'حظر بروتوكول USB HID غير الموثق وتعطيل منافذ التخزين لمنع سحب البيانات.',
      descriptionEn: 'Block unauthorized HID simulation devices and enforce strict USB port authorization.',
      category: 'physical_security',
      mitreRef: 'T1200 (Hardware Additions)',
      steps: [
        {
          stepId: 1,
          title: 'فصل الجهاز المريب برمجياً من شجرة USB',
          titleEn: 'Deauthorize suspicious USB device from bus',
          command: 'echo 0 > /sys/bus/usb/devices/1-7/authorized',
          description: 'قطع الطاقة ونقل البيانات فوراً عن الجهاز المتصل عبر النواة.',
          descriptionEn: 'Revoke device authorization at kernel level.',
          completed: false,
          automated: true,
        },
        {
          stepId: 2,
          title: 'تفعيل قاعدة USBGuard لحظر أجهزة HID الجديدة تلقائياً',
          titleEn: 'Enable USBGuard daemon with default reject policy',
          command: 'usbguard generate-policy > /etc/usbguard/rules.conf && systemctl restart usbguard',
          description: 'منع أي لوحة مفاتيح أو فلاش جديد من العمل دون موافقة مسبقة.',
          descriptionEn: 'Enforce white-list policy for all newly plugged physical peripherals.',
          completed: false,
          automated: true,
        },
      ],
    },
  ]);

  // Threat Intelligence & CVE Database
  readonly threatIntel = signal<ThreatIntelItem[]>([
    {
      id: 'ti-1',
      cveId: 'CVE-2024-6387',
      title: 'ثغرة regreSSHion في خادم OpenSSH (تنفيذ كود كـ Root)',
      severity: 'critical',
      cvss: 9.8,
      affected: 'OpenSSH 8.5p1 to 9.7p1 (glibc-based Linux)',
      published: '2024-07-01',
      description: 'ثغرة سباق الإشارات (Signal handler race condition) في خادم sshd على أنظمة Linux المعتمدة على glibc، تسمح بتنفيذ كود غير مصرح به بصلاحيات root دون توثيق.',
      descriptionEn: 'A signal handler race condition in OpenSSH daemon (sshd) allows unauthenticated remote attackers to execute arbitrary code with root privileges on glibc-based Linux systems.',
      exploitAvailable: true,
      pocSnippet: '# Exploit PoC: Race condition trigger via SIGALRM timing exhaustion\n# Reference: Qualys Security Advisory QSA-2024-07-01',
      mitreTactic: 'Initial Access / Privilege Escalation (T1068)',
    },
    {
      id: 'ti-2',
      cveId: 'CVE-2023-4911',
      title: 'ثغرة Looney Tunables في glibc (تصعيد صلاحيات محلي لـ Root)',
      severity: 'high',
      cvss: 7.8,
      affected: 'GNU C Library (glibc) 2.34 to 2.38',
      published: '2023-10-03',
      description: 'فيضان في مخزن الذاكرة المؤقتة (Buffer overflow) في معالج متغير البيئة GLIBC_TUNABLES أثناء تحميل البرامج التنفيذية ذات صلاحية SUID.',
      descriptionEn: 'Buffer overflow in the GNU C Library dynamic loader while handling GLIBC_TUNABLES environment variable in SUID binaries.',
      exploitAvailable: true,
      pocSnippet: 'env -i "GLIBC_TUNABLES=glibc.pthread.rseq=1:glibc.pthread.rseq=1:" /usr/bin/su --help',
      mitreTactic: 'Privilege Escalation (T1548.001)',
    },
    {
      id: 'ti-3',
      cveId: 'CVE-2024-3094',
      title: 'الباب الخلفي لمكتبة XZ Utils (الوصول الخفي عبر SSH)',
      severity: 'critical',
      cvss: 10.0,
      affected: 'liblzma 5.6.0 & 5.6.1 in bleeding-edge distributions',
      published: '2024-03-29',
      description: 'باب خلفي تم حقنه بشكل معقد في أكواد المصدر وحزم الإصدار لمكتبة XZ Utils يعترض توثيق RSA في sshd للسماح بتنفيذ أوامر سرية.',
      descriptionEn: 'Malicious supply-chain backdoor injected into upstream xz/liblzma builds intercepting OpenSSH RSA authentication.',
      exploitAvailable: true,
      pocSnippet: 'strings /usr/lib/x86_64-linux-gnu/liblzma.so.5 | grep -i "test-case"',
      mitreTactic: 'Supply Chain Compromise (T1195.002)',
    },
    {
      id: 'ti-4',
      cveId: 'CVE-2023-38606',
      title: 'استغلال تسريب الذاكرة لخدمات الويب عبر HTTP Request Smuggling',
      severity: 'medium',
      cvss: 6.5,
      affected: 'Reverse Proxy / Reverse Caching Nodes',
      published: '2023-08-14',
      description: 'عدم اتساق في تحليل رؤوس Transfer-Encoding و Content-Length بين الخوادم الوسيطة وخوادم التطبيقات.',
      descriptionEn: 'Discrepancy in handling Transfer-Encoding headers leading to request smuggling and session token desync.',
      exploitAvailable: false,
      mitreTactic: 'Defense Evasion (T1036)',
    },
  ]);

  // Cyber Library / Local Knowledge Base
  readonly knowledgeBase = signal<KnowledgeDoc[]>([
    {
      id: 'kb-1',
      title: 'دليل تأمين أنظمة لينكس وفق معيار CIS Linux Benchmark',
      titleEn: 'CIS Linux Benchmark Hardening Guide',
      category: 'System Hardening',
      standard: 'CIS Benchmark v2.0',
      summary: 'مجموعة التوصيات المعتمدة عالمياً لتأمين نواة لينكس، بروتوكولات الشبكة، ومحددات الوصول للملفات الحساسة.',
      summaryEn: 'Globally recognized baseline recommendations for securing Linux kernels, network stacks, and sensitive file permissions.',
      content: `1. تأمين نظام الملفات:
- فصل /var, /tmp, /home في أقسام مستقلة.
- تعيين خيارات noexec, nosuid, nodev على قسم /tmp لمنع تشغيل السكربتات الخبيثة.

2. تأمين بروتوكول SSH:
- تغيير المنفذ الافتراضي إلى منفذ غير قياسي.
- منع PermitRootLogin و PasswordAuthentication.
- استخدام خوارزميات التشفير الحديثة: Ciphers chacha20-poly1305@openssh.com.

3. المراقبة والتدقيق:
- تفعيل خدمة auditd مع قواعد مراقبة الملفات الحساسة (/etc/shadow, /etc/sudoers).`,
      contentEn: `1. Filesystem Hardening:
- Separate /var, /tmp, and /home into dedicated mount points.
- Apply noexec, nosuid, nodev mount options on /tmp.

2. SSH Protocol Hardening:
- Enforce PermitRootLogin no and PasswordAuthentication no.
- Adopt modern ciphers (chacha20-poly1305, curve25519-sha256).

3. Audit & Logging:
- Enable auditd daemon with monitored watchers on /etc/shadow, /etc/sudoers.`,
      tags: ['cis', 'linux', 'hardening', 'auditd'],
    },
    {
      id: 'kb-2',
      title: 'استراتيجية كشف والتعامل مع أجهزة BadUSB و Rubber Ducky',
      titleEn: 'BadUSB & Rubber Ducky Detection and Defense',
      category: 'Hardware Security',
      standard: 'NIST SP 800-111',
      summary: 'كيفية عمل أجهزة حقن الأوامر التلقائية عبر منافذ USB وطرق إحباطها قبل تنفيذ الهجوم.',
      summaryEn: 'Mechanics of automated keystroke injection devices and defensive countermeasures.',
      content: `تعمل أجهزة BadUSB عبر التخفي في هيئة لوحة مفاتيح HID (Human Interface Device). فور إدخال الجهاز، ترسل النواة أمر تعريف يتبعه قيام الجهاز بحقن أوامر عبر سطر الأوامر بسرعة تفوق 1000 حرف في الدقيقة.

طرق الحماية المعتمدة في AI AYFAM:
- USBGuard: حظر أي جهاز USB جديد تلقائياً حتى يقوم المستخدم بتفويضه يدوياً.
- تحليل سرعة الإدخال: رصد الكتابة الفائقة غير الطبيعية وتجميد جلسة المستخدم فوراً.
- تفتيش الأقراص المركبة: البحث عن ملفات autorun.inf أو السكربتات المبرمجة بالامتدادات .sh, .py, .ps1.`,
      contentEn: `BadUSB devices pose as standard HID keyboards to bypass security controls and inject terminal commands at inhuman speeds (>1000 CPM).

AI AYFAM Countermeasures:
- USBGuard whitelist policy enforcement.
- Real-time keystroke timing heuristics.
- Deep forensic scanning of newly mounted partitions for autorun scripts and payloads.`,
      tags: ['badusb', 'usbguard', 'hardware', 'forensics'],
    },
    {
      id: 'kb-3',
      title: 'مصفوفة MITRE ATT&CK: تصنيف الأساليب وتتبع المسارات',
      titleEn: 'MITRE ATT&CK Matrix Mapping in Defense',
      category: 'Threat Modeling',
      standard: 'MITRE Enterprise Matrix v14',
      summary: 'فهم أساليب المهاجمين من نقطة الدخول الأولى وحتى استخراج البيانات الحساسة.',
      summaryEn: 'Mapping threat actor techniques from Initial Access to Data Exfiltration.',
      content: `تغطي مصفوفة MITRE ATT&CK التكتيكات التالية:
1. الوصول الأولي (Initial Access - TA0001): استغلال الخدمات العامة، التصيد، أجهزة USB.
2. التنفيذ (Execution - TA0002): استخدام مترجمات الأوامر مثل bash و sh و python.
3. الاستقرار والاستمرار (Persistence - TA0003): إنشاء مهام Cron، خدمات systemd مشبوهة، ومفاتيح SSH مرخصة.
4. تصعيد الصلاحيات (Privilege Escalation - TA0004): استغلال SUID ثنائية، ثغرات النواة، إعدادات sudoers الخاطئة.
5. الإخفاء (Defense Evasion - TA0005): مسح سجلات التاريخ، تزوير أسماء العمليات.`,
      contentEn: `The MITRE ATT&CK framework categorizes adversarial techniques:
1. Initial Access (TA0001): Public service exploits, phishing, malicious USB.
2. Execution (TA0002): Command and scripting interpreters (bash, python).
3. Persistence (TA0003): Scheduled cron jobs, rogue systemd services, authorized keys.
4. Privilege Escalation (TA0004): Exploitation for privilege escalation (SUID, sudoers misconfigs).
5. Defense Evasion (TA0005): Clearing history, process masquerading.`,
      tags: ['mitre', 'att&ck', 'tactics', 'threat-hunting'],
    },
  ]);

  // AI Security Assistant Chat Messages
  readonly chatMessages = signal<ChatMessage[]>([
    {
      id: 'c-1',
      sender: 'agent',
      text: 'أهلاً بك في AI AYFAM. أنا وكيلك الذكي للأمن السيبراني والدفاع عن النظام. كيف يمكنني مساعدتك اليوم؟ يمكنك سؤالي عن نتائج الفحص، أوامر الترقيع، أو تحليل التهديدات.',
      textEn: 'Welcome to AI AYFAM. I am your specialized cybersecurity operations agent. How can I assist you today? You can ask me about audit findings, remediation commands, or threat intelligence.',
      timestamp: '10:00:10',
    },
  ]);

  // Active scan progress
  readonly scanProgress = signal<number>(0);
  readonly isScanning = signal<boolean>(false);
  readonly scanPhaseText = signal<string>('');
  readonly scanError = signal<string | null>(null);
  readonly scanSource = signal<'local-scanners' | 'demo-data'>('demo-data');

  // Derived Computed Stats
  readonly findingsCount = computed(() => {
    const list = this.findings().filter((f) => !f.fixed);
    return {
      total: list.length,
      critical: list.filter((f) => f.severity === 'critical').length,
      high: list.filter((f) => f.severity === 'high').length,
      medium: list.filter((f) => f.severity === 'medium').length,
      low: list.filter((f) => f.severity === 'low').length,
      info: list.filter((f) => f.severity === 'info').length,
      fixed: this.findings().filter((f) => f.fixed).length,
    };
  });

  readonly postureScore = computed(() => {
    const active = this.findings().filter((f) => !f.fixed);
    let penalty = 0;
    for (const item of active) {
      if (item.severity === 'critical') penalty += 25;
      else if (item.severity === 'high') penalty += 15;
      else if (item.severity === 'medium') penalty += 7;
      else if (item.severity === 'low') penalty += 3;
    }
    const score = Math.max(12, 100 - penalty);
    return score;
  });

  // Switch locale
  setLocale(l: 'ar' | 'en'): void {
    this.locale.set(l);
    if (typeof document !== 'undefined') {
      document.documentElement.lang = l;
      document.documentElement.dir = l === 'ar' ? 'rtl' : 'ltr';
    }
  }

  // Switch View
  setView(view: string): void {
    this.currentView.set(view);
  }

  // Remediate a single finding
  remediateFinding(id: string): void {
    this.findings.update((current) =>
      current.map((f) => (f.id === id ? { ...f, fixed: true } : f))
    );

    const f = this.findings().find((item) => item.id === id);
    const title = f ? f.title : id;
    const titleEn = f ? f.titleEn : id;

    this.addAuditEvent({
      id: `fix-${Date.now()}`,
      timestamp: new Date().toLocaleTimeString(),
      level: 'FIX',
      message: `تم تعليم النتيجة كمراجعة محلية فقط (لم يُنفذ أمر النظام): ${title}`,
      messageEn: `Finding marked as locally reviewed only (no system command executed): ${titleEn}`,
      category: 'auto_fix',
    });
  }

  // Auto-reaction fix all
  remediateAll(): void {
    this.findings.update((current) =>
      current.map((f) => ({ ...f, fixed: true }))
    );

    this.addAuditEvent({
      id: `fix-all-${Date.now()}`,
      timestamp: new Date().toLocaleTimeString(),
      level: 'ACTION',
      message: 'تم تعليم النتائج كمراجعة محلية فقط — لم تُنفذ أوامر على النظام',
      messageEn: 'Findings marked as locally reviewed only — no system commands were executed',
      category: 'autoreactor',
    });
  }

  // Add audit event
  addAuditEvent(event: AuditEvent): void {
    this.auditEvents.update((list) => [event, ...list.slice(0, 150)]);
  }

  // USB Authorization Toggle
  toggleUsbAuthorization(id: string): void {
    this.usbDevices.update((list) =>
      list.map((device) => {
        if (device.id === id) {
          const nextAuth = !device.authorized;
          const statusAr = nextAuth ? 'تفويض واعتماد' : 'حظر وعزل';
          const statusEn = nextAuth ? 'Authorized' : 'Blocked';
          this.addAuditEvent({
            id: `usb-auth-${Date.now()}`,
            timestamp: new Date().toLocaleTimeString(),
            level: nextAuth ? 'ACTION' : 'WARN',
            message: `تم تغيير حالة جهاز USB [${device.name}]: ${statusAr}`,
            messageEn: `USB device [${device.nameEn}] status changed: ${statusEn}`,
            category: 'usb_control',
          });
          return { ...device, authorized: nextAuth };
        }
        return device;
      })
    );
  }

  // Toggle Playbook step completion
  togglePlaybookStep(playbookId: string, stepId: number): void {
    this.playbooks.update((list) =>
      list.map((pb) => {
        if (pb.id === playbookId) {
          const updatedSteps = pb.steps.map((st) =>
            st.stepId === stepId ? { ...st, completed: !st.completed } : st
          );
          return { ...pb, steps: updatedSteps };
        }
        return pb;
      })
    );
  }

  // Execute real local security checks through the protected Python bridge.
  async runSecurityScan(scanType: string, profile: 'full' | 'network' | 'system' | 'logs' = 'full', target = '127.0.0.1'): Promise<void> {
    if (this.isScanning()) return;
    this.isScanning.set(true);
    this.scanError.set(null);
    this.scanProgress.set(10);
    this.scanPhaseText.set(
      this.locale() === 'ar' ? 'فحص النواة والمنافذ المفتوحة...' : 'Scanning kernel & network sockets...'
    );

    this.addAuditEvent({
      id: `scan-${Date.now()}`,
      timestamp: new Date().toLocaleTimeString(),
      level: 'INFO',
      message: `بدء فحص أمني جديد: [${scanType}]`,
      messageEn: `Initiated security scan: [${scanType}]`,
      category: 'scanner',
    });

    try {
      this.scanProgress.set(35);
      this.scanPhaseText.set(this.locale() === 'ar' ? 'تشغيل فحوص النظام والشبكة الفعلية...' : 'Running real system and network checks...');
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ profile, target }),
      });
      const payload = (await response.json().catch(() => ({}))) as Partial<ScanResponse> & { error?: string };
      if (!response.ok || !payload.ok || !Array.isArray(payload.findings)) {
        throw new Error(payload.error || `scan_failed_${response.status}`);
      }
      this.scanProgress.set(90);
      this.findings.set(payload.findings);
      this.scanSource.set('local-scanners');
      this.telemetry.update((t) => ({ ...t, lastAuditTime: new Date().toLocaleTimeString(), status: 'idle' }));
      this.addAuditEvent({
        id: `scan-done-${Date.now()}`,
        timestamp: new Date().toLocaleTimeString(),
        level: 'INFO',
        message: `اكتمل الفحص الفعلي: ${payload.findings.length} نتيجة، خلال ${payload.elapsedMs ?? 0} مللي ثانية.`,
        messageEn: `Real scan completed: ${payload.findings.length} findings in ${payload.elapsedMs ?? 0} ms.`,
        category: 'scanner',
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : 'تعذر تنفيذ الفحص';
      this.scanError.set(message);
      this.addAuditEvent({
        id: `scan-error-${Date.now()}`,
        timestamp: new Date().toLocaleTimeString(),
        level: 'WARN',
        message: 'تعذر الوصول إلى الفاحص المحلي؛ لم يتم استبدال النتائج الحالية ببيانات وهمية.',
        messageEn: 'Local scanner unavailable; existing findings were kept and no simulated result was inserted.',
        category: 'scanner',
      });
    } finally {
      this.scanProgress.set(100);
      this.isScanning.set(false);
      this.scanPhaseText.set(this.locale() === 'ar' ? 'انتهى الفحص' : 'Scan complete');
    }
  }

  // Send Chat Prompt to AI Security Assistant
  async sendChatMessage(query: string): Promise<void> {
    if (!query.trim()) return;

    const userMsg: ChatMessage = {
      id: `u-${Date.now()}`,
      sender: 'user',
      text: query,
      textEn: query,
      timestamp: new Date().toLocaleTimeString(),
    };
    this.chatMessages.update((msgs) => [...msgs, userMsg]);

    const context = this.findings().filter((finding) => !finding.fixed).slice(0, 12)
      .map((finding) => `${finding.severity}: ${finding.title} — ${finding.detail}`).join('\n');
    const remoteReply = await this.assistant.ask(`${query}\n\nنتائج الفحص الحالية (استخدمها كدليل ولا تفترض ما ليس فيها):\n${context || 'لا توجد نتائج نشطة.'}`);
    if (remoteReply && 'answer' in remoteReply) {
      const agentMsg: ChatMessage = {
        id: `a-${Date.now()}`,
        sender: 'agent',
        text: remoteReply.answer,
        textEn: remoteReply.answer,
        timestamp: new Date().toLocaleTimeString(),
      };
      this.chatMessages.update((msgs) => [...msgs, agentMsg]);
      return;
    }

    // Generate intelligent contextual response
    setTimeout(() => {
      let replyAr = '';
      let replyEn = '';
      let cmd: string | undefined = undefined;

      const q = query.toLowerCase();
      if (q.includes('ssh') || q.includes('سرفيس') || q.includes('روت')) {
        replyAr = 'لحماية خادم SSH بأفضل ممارسة:\n1. عطل PermitRootLogin في /etc/ssh/sshd_config.\n2. عطل PasswordAuthentication واعتمد على مفاتيح Ed25519.\n3. اضبط سجن Fail2Ban لمنع هجمات التخمين.';
        replyEn = 'To secure OpenSSH following CIS benchmark:\n1. Set PermitRootLogin no in /etc/ssh/sshd_config.\n2. Set PasswordAuthentication no and require Ed25519 keys.\n3. Enable Fail2Ban jail to throttle brute-force attempts.';
        cmd = "sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && systemctl reload sshd";
      } else if (q.includes('usb') || q.includes('فلاش') || q.includes('باد')) {
        replyAr = 'أجهزة BadUSB تحاكي أجهزة HID لحقن أكواد سريعة. يوصى بتفعيل أداة USBGuard لحظر أي جهاز جديد تلقائياً حتى توافق عليه.';
        replyEn = 'BadUSB hardware masquerades as HID keyboards to inject shell scripts. Recommended countermeasure is deploying USBGuard with default-block whitelist policy.';
        cmd = 'usbguard generate-policy > /etc/usbguard/rules.conf && systemctl restart usbguard';
      } else if (q.includes('firewall') || q.includes('جدار') || q.includes('ufw')) {
        replyAr = 'جدار الحماية UFW معطل حالياً. قم بتفعيل سياسة الرفض للوارد والسماح فقط بالمنافذ الأساسية (22 SSH, 443 HTTPS).';
        replyEn = 'UFW firewall is inactive. Enable default incoming deny policy and whitelist only necessary operational ports.';
        cmd = 'ufw default deny incoming && ufw default allow outgoing && ufw allow 22/tcp && ufw allow 443/tcp && ufw --force enable';
      } else if (q.includes('suid') || q.includes('صلاحيات') || q.includes('gtfobins')) {
        replyAr = 'تم العثور على ملف /usr/local/bin/backup_exec يحمل البت +s، وهو معرض للاستغلال لتصعيد الصلاحيات. قم بنزع بت SUID منه.';
        replyEn = 'Binary /usr/local/bin/backup_exec contains SUID permission bit. Strip SUID to prevent local privilege escalation.';
        cmd = 'chmod u-s /usr/local/bin/backup_exec';
      } else {
        replyAr = `بناءً على نتائج التدقيق الحالية، درجة الأمان هي (${this.postureScore()}%). أكثر نقطة حرجة تتطلب تدخلك الفوري هي إعدادات SSH وجدار الحماية UFW. يمكنك النقر على "إصلاح فوري" لتأمينها مباشرة.`;
        replyEn = `Based on current audit telemetry, your security score is (${this.postureScore()}%). The most critical exposure is SSH root login and inactive UFW firewall. Use Auto-Reactor to harden immediately.`;
        cmd = 'ufw --force enable && sed -i "s/^PermitRootLogin.*/PermitRootLogin no/" /etc/ssh/sshd_config';
      }

      const agentMsg: ChatMessage = {
        id: `a-${Date.now()}`,
        sender: 'agent',
        text: replyAr,
        textEn: replyEn,
        timestamp: new Date().toLocaleTimeString(),
        recommendedCommand: cmd,
      };
      this.chatMessages.update((msgs) => [...msgs, agentMsg]);
    }, 500);
  }
}

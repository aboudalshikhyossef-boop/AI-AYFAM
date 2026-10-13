import {
  ChangeDetectionStrategy,
  Component,
  computed,
  inject,
  signal,
} from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormControl, FormGroup, ReactiveFormsModule } from '@angular/forms';
import { MatIconModule } from '@angular/material/icon';
import { SecurityStateService } from './services/security-state.service';
import { Splash } from './live-ui';
import {
  Finding,
  UsbDevice,
  Playbook,
  ThreatIntelItem,
  KnowledgeDoc,
} from './models/security.model';

@Component({
  selector: 'app-root',
  imports: [CommonModule, ReactiveFormsModule, MatIconModule, Splash],
  templateUrl: './app.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class App {
  readonly state = inject(SecurityStateService);

  // Live clock (updated per second)
  readonly clockTime = signal('');
  readonly clockDate = signal('');
  private clockTimer: ReturnType<typeof setInterval> | undefined;

  // Mobile nav drawer state
  readonly mobileNavOpen = signal(false);

  // Mobile navigation config (small screens)
  readonly mobileNav = () => [
    { id: 'dashboard', icon: 'dashboard', ar: 'العمليات', en: 'Ops' },
    { id: 'scans', icon: 'security', ar: 'الفحوصات', en: 'Scans' },
    { id: 'usb', icon: 'usb', ar: 'الأجهزة', en: 'Devices' },
    { id: 'tools', icon: 'terminal', ar: 'الترسانة', en: 'Arsenal' },
    { id: 'chat', icon: 'forum', ar: 'المحادثة', en: 'Chat' },
    { id: 'playbooks', icon: 'alt_route', ar: 'الخطط', en: 'Playbooks' },
    { id: 'library', icon: 'menu_book', ar: 'المكتبة', en: 'Library' },
    { id: 'reports', icon: 'assessment', ar: 'التقارير', en: 'Reports' },
    { id: 'settings', icon: 'tune', ar: 'الإعدادات', en: 'Settings' },
  ];

  refreshClock(): void {
    const now = new Date();
    const loc = this.state.locale() === 'ar' ? 'ar-SY' : 'en-US';
    const time = new Intl.DateTimeFormat(loc, { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }).format(now);
    const date = new Intl.DateTimeFormat(loc, { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' }).format(now);
    this.clockTime.set(time);
    this.clockDate.set(date);
  }

  // Search & Filter controls
  readonly findingFilter = signal<'all' | 'critical' | 'high' | 'medium' | 'low'>('all');
  readonly cveSearchQuery = signal<string>('');
  readonly selectedDoc = signal<KnowledgeDoc | null>(null);
  readonly selectedThreat = signal<ThreatIntelItem | null>(null);

  // Copied alert state
  readonly copiedCommand = signal<string | null>(null);

  // Reactive Chat Form
  readonly chatForm = new FormGroup({
    message: new FormControl('', { nonNullable: true }),
  });

  // Reactive Scan Target Form
  readonly scanForm = new FormGroup({
    targetHost: new FormControl('127.0.0.1', { nonNullable: true }),
    scanProfile: new FormControl('full', { nonNullable: true }),
  });

  // Filtered findings computed
  readonly filteredFindings = computed(() => {
    const list = this.state.findings();
    const filter = this.findingFilter();
    if (filter === 'all') return list;
    return list.filter((f) => f.severity === filter);
  });

  // Filtered threat intel
  readonly filteredThreats = computed(() => {
    const list = this.state.threatIntel();
    const q = this.cveSearchQuery().toLowerCase().trim();
    if (!q) return list;
    return list.filter(
      (t) =>
        t.cveId.toLowerCase().includes(q) ||
        t.title.toLowerCase().includes(q) ||
        t.affected.toLowerCase().includes(q) ||
        t.mitreTactic.toLowerCase().includes(q)
    );
  });

  // Selected Playbook for Detail Modal/Drawer
  readonly activePlaybook = signal<Playbook | null>(null);

  constructor() {
    // Initialize live clock (1s interval)
    this.refreshClock();
    this.clockTimer = setInterval(() => this.refreshClock(), 1000);

    // Set default selected items
    const docs = this.state.knowledgeBase();
    if (docs.length > 0) {
      this.selectedDoc.set(docs[0]);
    }
    const threats = this.state.threatIntel();
    if (threats.length > 0) {
      this.selectedThreat.set(threats[0]);
    }
    const playbooks = this.state.playbooks();
    if (playbooks.length > 0) {
      this.activePlaybook.set(playbooks[0]);
    }
  }

  // Quick Action: Send chat
  onSubmitChat(): void {
    const text = this.chatForm.controls.message.value;
    if (text.trim()) {
      this.state.sendChatMessage(text);
      this.chatForm.reset({ message: '' });
    }
  }

  // Send pre-built prompt
  sendPrebuiltPrompt(prompt: string): void {
    this.state.sendChatMessage(prompt);
  }

  // Trigger quick scan from toolbar
  onTriggerScan(): void {
    const profile = this.scanForm.controls.scanProfile.value;
    this.state.runSecurityScan(profile === 'full' ? 'تدقيق شامل للنظام' : 'فحص شبكة سريع');
  }

  // Copy command helper
  copyToClipboard(cmd: string): void {
    if (typeof navigator !== 'undefined' && navigator.clipboard) {
      navigator.clipboard.writeText(cmd);
      this.copiedCommand.set(cmd);
      setTimeout(() => {
        this.copiedCommand.set(null);
      }, 2500);
    }
  }

  // Print/Export Report
  exportReport(format: 'print' | 'json'): void {
    if (format === 'print') {
      if (typeof window !== 'undefined') {
        window.print();
      }
    } else {
      const data = {
        metadata: {
          app: 'AI AYFAM Security Operations Center',
          exportedAt: new Date().toISOString(),
          hostname: this.state.telemetry().hostname,
          postureScore: this.state.postureScore(),
        },
        findings: this.state.findings(),
        usbInventory: this.state.usbDevices(),
        auditEvents: this.state.auditEvents(),
      };
      const blob = new Blob([JSON.stringify(data, null, 2)], {
        type: 'application/json',
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `ayfam_security_report_${Date.now()}.json`;
      a.click();
      URL.revokeObjectURL(url);
    }
  }
}

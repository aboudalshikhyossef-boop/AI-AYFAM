import {
  ChangeDetectionStrategy,
  Component,
  computed,
  inject,
  OnDestroy,
  signal,
} from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormControl, FormGroup, ReactiveFormsModule } from '@angular/forms';
import { MatIconModule } from '@angular/material/icon';
import { SecurityStateService } from './services/security-state.service';
import {
  Finding,
  UsbDevice,
  Playbook,
  ThreatIntelItem,
  KnowledgeDoc,
} from './models/security.model';

@Component({
  selector: 'app-root',
  imports: [CommonModule, ReactiveFormsModule, MatIconModule],
  templateUrl: './app.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class App implements OnDestroy {
  readonly state = inject(SecurityStateService);
  private readonly googleCseTimer: ReturnType<typeof setInterval>;
  private googleCseRendered = false;

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
    // The tools view is created with Angular control flow, so Google CSE needs
    // explicit rendering after its host element appears in the DOM.
    this.googleCseTimer = setInterval(() => this.renderGoogleCse(), 250);

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

  ngOnDestroy(): void {
    clearInterval(this.googleCseTimer);
  }

  private renderGoogleCse(): void {
    if (typeof window === 'undefined') return;
    const host = document.getElementById('ayfam-google-cse');
    if (!host) {
      this.googleCseRendered = false;
      return;
    }
    if (this.googleCseRendered) return;
    const cse = (window as Window & {
      google?: { search?: { cse?: { element?: { render?: (options: { div: string }) => void } } } };
    }).google?.search?.cse?.element;
    if (!host || !cse?.render) return;
    cse.render({ div: 'ayfam-google-cse' });
    this.googleCseRendered = true;
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

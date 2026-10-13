import { DOCUMENT } from '@angular/common';
import { inject, signal, Component, OnDestroy, OnInit, NgZone } from '@angular/core';

/**
 * DynamicAccent —
 * Slowly cycles the global --accent-hue CSS variable so the entire
 * interface pulses through a curated futuristic palette.
 */
const ACCENT_HUES = [190, 210, 265, 292, 320, 350, 165];

@Component({
  selector: 'app-splash',
  standalone: true,
  template: `
    <div class="fixed inset-0 z-[9999] flex items-center justify-center bg-[#03050c]/90 backdrop-blur-md transition-all duration-700"
         [class.opacity-0]="!visible()"
         [class.pointer-events-none]="!visible()"
         [class.-translate-y-6]="!visible()">
      <div class="flex flex-col items-center gap-8 px-6 text-center">

        <!-- Animated shield / hexagon emblem -->
        <div class="relative">
          <svg width="104" height="104" viewBox="0 0 100 100" class="drop-shadow-[0_0_28px_rgba(34,211,238,0.4)]">
            <!-- Outer rotating ring -->
            <circle cx="50" cy="50" r="46" fill="none"
              stroke="url(#ringGrad)" stroke-width="1.5" stroke-dasharray="12 8"
              class="origin-center" style="animation: ayfam-spin 12s linear infinite; transform-origin: 50px 50px;" />
            <!-- Middle hexagon outline -->
            <polygon points="50,8 88,30 88,70 50,92 12,70 12,30" fill="none"
              stroke="url(#ringGrad)" stroke-width="1" opacity="0.5" />
            <!-- Core shield -->
            <path d="M50 22 L70 32 V50 C70 65 61 73 50 78 C39 73 30 65 30 50 V32 Z"
              fill="url(#coreGrad)" stroke="url(#ringGrad)" stroke-width="1.5" />
            <path d="M42 50 L48 56 L60 42" fill="none" stroke="#f8fafc" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" />
            <defs>
              <linearGradient id="ringGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stop-color="hsl(var(--accent-hue) 90% 60%)" />
                <stop offset="100%" stop-color="hsl(var(--accent2-hue) 80% 70%)" />
              </linearGradient>
              <linearGradient id="coreGrad" x1="0%" y1="0%" x2="0%" y2="100%">
                <stop offset="0%" stop-color="hsl(var(--accent-hue) 80% 35% / 0.5)" />
                <stop offset="100%" stop-color="hsl(var(--accent2-hue) 70% 25% / 0.6)" />
              </linearGradient>
            </defs>
          </svg>
          <!-- Pulse halo -->
          <div class="absolute inset-0 rounded-full border border-cyan-400/20 animate-ping-slow"></div>
        </div>

        <!-- Title -->
        <div>
          <h1 class="text-4xl font-extrabold tracking-tight gradient-text-animated mb-2">
            AI AYFAM
          </h1>
          <p class="text-sm text-slate-400 font-mono tracking-wide uppercase">
            {{ subtitle() }}
          </p>
        </div>

        <!-- Loading dots -->
        <div class="flex items-center gap-2">
          <span class="w-2 h-2 rounded-full bg-cyan-400 animate-bounce" style="animation-delay: 0ms"></span>
          <span class="w-2 h-2 rounded-full bg-violet-400 animate-bounce" style="animation-delay: 150ms"></span>
          <span class="w-2 h-2 rounded-full bg-pink-400 animate-bounce" style="animation-delay: 300ms"></span>
        </div>

        <!-- Progress bar -->
        <div class="w-56 h-1 rounded-full bg-slate-800/80 overflow-hidden relative">
          <div class="h-full rounded-full bg-gradient-to-r from-cyan-400 via-violet-400 to-pink-400 transition-all duration-300"
               [style.width.%]="progress()"></div>
        </div>
      </div>
    </div>

    <style>
      @keyframes ayfam-spin { to { transform: rotate(360deg); } }
      .animate-ping-slow {
        animation: ayfam-ping 2.4s cubic-bezier(0, 0, 0.2, 1) infinite;
      }
      @keyframes ayfam-ping {
        0% { transform: scale(0.8); opacity: 0.8; }
        75%, 100% { transform: scale(1.4); opacity: 0; }
      }
    </style>
  `,
})
export class Splash implements OnInit, OnDestroy {
  private readonly doc = inject(DOCUMENT);
  private readonly zone = inject(NgZone);
  private timer?: ReturnType<typeof setInterval>;
  private cycleTimer?: ReturnType<typeof setInterval>;
  private timeout?: ReturnType<typeof setTimeout>;

  readonly visible = signal(true);
  readonly progress = signal(0);
  readonly subtitle = signal('SECURITY OPERATIONS CENTER');

  ngOnInit(): void {
    this.zone.runOutsideAngular(() => {
      // Fake boot progress then fade splash
      let p = 0;
      this.timer = setInterval(() => {
        p = Math.min(p + Math.random() * 14, 100);
        this.progress.set(Math.round(p));
        if (p >= 100) {
          this.clearTimer(this.timer!);
          this.timeout = setTimeout(() => {
            this.visible.set(false);
            this.startAmbientCycle();
          }, 500);
        }
      }, 260);
    });
  }

  ngOnDestroy(): void {
    this.clearTimer(this.timer!);
    this.clearTimer(this.cycleTimer!);
    if (this.timeout) clearTimeout(this.timeout);
  }

  private clearTimer(t: ReturnType<typeof setInterval>): void {
    if (t) clearInterval(t);
  }

  private startAmbientCycle(): void {
    let idx = 1;
    this.cycleTimer = setInterval(() => {
      idx = (idx + 1) % ACCENT_HUES.length;
      const hue = ACCENT_HUES[idx];
      const root = this.doc.documentElement;
      root.style.setProperty('--accent-hue', `${hue}`);
      root.style.setProperty('--accent2-hue', `${(hue + 80) % 360}`);
    }, 12000);
  }
}


/**
 * LiveClock — displays current time and date, updating every second,
 * localized to Arabic or English based on current locale signal.
 */
export function createLiveClock(getLocale: () => string) {
  const time = signal('');
  const date = signal('');
  const zone = inject(NgZone);
  let timer: ReturnType<typeof setInterval> | undefined;

  function tick(): void {
    const now = new Date();
    const loc = getLocale() === 'ar' ? 'ar-SY' : 'en-US';
    time.set(
      new Intl.DateTimeFormat(loc, {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false,
      }).format(now),
    );
    date.set(
      new Intl.DateTimeFormat(loc, {
        weekday: 'long',
        day: 'numeric',
        month: 'long',
        year: 'numeric',
      }).format(now),
    );
  }

  zone.runOutsideAngular(() => {
    tick();
    timer = setInterval(tick, 1000);
  });

  return {
    time,
    date,
    destroy(): void {
      if (timer) clearInterval(timer);
    },
  };
}

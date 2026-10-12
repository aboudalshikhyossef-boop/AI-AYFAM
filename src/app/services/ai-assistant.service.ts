import { Injectable } from '@angular/core';

export interface AssistantReply {
  provider: 'openai' | 'gemini' | 'local';
  answer: string;
}

@Injectable({ providedIn: 'root' })
export class AiAssistantService {
  async ask(prompt: string): Promise<AssistantReply | null> {
    try {
      const response = await fetch('/api/assistant', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ prompt }),
      });
      if (!response.ok) return null;
      const payload = (await response.json()) as Partial<AssistantReply>;
      if (typeof payload.answer !== 'string' || !payload.answer.trim()) return null;
      const provider = payload.provider === 'openai' || payload.provider === 'gemini' ? payload.provider : 'local';
      return { provider, answer: payload.answer };
    } catch {
      // The cockpit remains useful offline and uses its local knowledge base.
      return null;
    }
  }
}

import { Injectable } from '@angular/core';

export interface AssistantReply {
  provider: 'openai' | 'gemini' | 'local';
  answer: string;
}

export interface AssistantFailure {
  message: string;
  status?: number;
}

@Injectable({ providedIn: 'root' })
export class AiAssistantService {
  async ask(prompt: string): Promise<AssistantReply | AssistantFailure | null> {
    try {
      const response = await fetch('/api/assistant', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ prompt }),
      });
      const payload = (await response.json().catch(() => ({}))) as Partial<AssistantReply> & { error?: string };
      if (!response.ok) {
        return { message: payload.error || `تعذر الاتصال بمساعد الذكاء (${response.status})`, status: response.status };
      }
      if (typeof payload.answer !== 'string' || !payload.answer.trim()) return null;
      const provider = payload.provider === 'openai' || payload.provider === 'gemini' ? payload.provider : 'local';
      return { provider, answer: payload.answer };
    } catch (error) {
      // The cockpit remains useful offline and uses its local knowledge base.
      return { message: error instanceof TypeError ? 'خادم AI AYFAM غير متاح حالياً؛ تم استخدام العقل المحلي.' : 'تعذر الوصول إلى خدمة الذكاء؛ تم استخدام العقل المحلي.' };
    }
  }
}

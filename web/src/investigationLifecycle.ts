import { useEffect, useState } from 'react';
import { ApiError } from './api';

/** One bounded group of reads/mutations. Retiring intent never cancels server work. */
export class InvestigationOwner {
  private generation = 0;
  private controllers = new Set<AbortController>();
  cancel() {
    this.generation += 1;
    for (const controller of this.controllers) controller.abort();
    this.controllers.clear();
  }
  async request<T>(task: (signal: AbortSignal) => Promise<T>, success: (value: T) => void, failure: (error: unknown) => void, timeout = 15000): Promise<void> {
    const generation = this.generation;
    const controller = new AbortController();
    this.controllers.add(controller);
    let timedOut = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    // Race explicitly: fetch adapters as well as browsers may ignore AbortSignal.
    let abort: () => void = () => {};
    const deadline = new Promise<never>((_, reject) => {
      abort = () => { clearTimeout(timer); reject(new Error(timedOut ? 'Request timed out; server outcome is unconfirmed.' : 'Request retired')); };
      controller.signal.addEventListener('abort', abort, { once: true });
      timer = setTimeout(() => { timedOut = true; controller.abort(); }, timeout);
    });
    try {
      const value = await Promise.race([task(controller.signal), deadline]);
      if (generation === this.generation && !controller.signal.aborted) success(value);
    } catch (error) {
      if (generation === this.generation && (!controller.signal.aborted || timedOut)) failure(error);
    } finally {
      clearTimeout(timer);
      controller.signal.removeEventListener('abort', abort);
      this.controllers.delete(controller);
    }
  }
}
export function useInvestigationOwner() {
  const [owner] = useState(() => new InvestigationOwner());
  useEffect(() => () => owner.cancel(), [owner]);
  return owner;
}
export const investigationScopeMessages = {
  UNAVAILABLE: '범위 포함 여부를 확인할 수 없습니다. 부재의 증거가 아닙니다. / Scope eligibility is unknown; this is not evidence of absence.',
  NOT_FOUND_IN_INSPECTED_SCOPE: '검사된 부분 출처에서 찾지 못했습니다. 전체 출처의 부재를 뜻하지 않습니다. / Not found in the inspected partial source; absence from the whole source is not established.',
  NOT_OBSERVED: '검사된 출처 범위에서 관측되지 않았습니다. IP나 C2의 부재를 뜻하지 않습니다. / Not observed in this inspected source scope; this does not establish absence of the IP or C2.',
};
const scopeErrors: Record<string, string> = {
  TARGET_SCOPE_UNAVAILABLE: investigationScopeMessages.UNAVAILABLE,
  TARGET_NOT_FOUND_IN_INSPECTED_SCOPE: investigationScopeMessages.NOT_FOUND_IN_INSPECTED_SCOPE,
  TARGET_NOT_OBSERVED: investigationScopeMessages.NOT_OBSERVED,
};
export const investigationError = (error: unknown) => error instanceof ApiError && Object.hasOwn(scopeErrors, error.code)
  ? `${error.code}: ${scopeErrors[error.code]}`
  : error instanceof Error ? error.message : 'Investigation request failed';

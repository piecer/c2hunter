import { ApiError } from './api';

export const historicalAccessDenied = (error: unknown) => error instanceof ApiError && (error.status === 401 || error.status === 403);
export const historicalConflict = (error: unknown) => error instanceof ApiError && error.status === 409;
export function historicalErrorText(error: Error, language: 'en' | 'ko') {
  if (historicalAccessDenied(error)) return language === 'ko'
    ? '접근이 거부되었습니다. 인증이 활성화된 서버에 ANALYST 또는 ADMIN 계정으로 로그인하세요.'
    : 'Access denied. Sign in with an ANALYST or ADMIN account on an authentication-enabled server.';
  if (historicalConflict(error)) return language === 'ko'
    ? '참조가 오래되었거나 충돌했습니다. 범위를 다시 불러오고 명시적으로 새 미리보기를 실행하세요. 자동 재시도하지 않습니다.'
    : 'Stale reference or conflict. Reload scopes and explicitly preview again. No automatic retry.';
  return `${language === 'ko' ? '과거 참조 요청 실패' : 'Historical reference request failed'}: ${error.message}`;
}

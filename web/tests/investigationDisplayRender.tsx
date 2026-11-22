import type { ReactNode } from 'react';
import { render as testingRender } from '@testing-library/react';
import { ReportLanguageContext } from '../src/reportLanguageContext';

/** Exercise single-language labels; stored producer prose remains untouched. */
export function render(ui: ReactNode) {
  return testingRender(ui, { wrapper: ({ children }) => <ReportLanguageContext.Provider value="en">{children}</ReportLanguageContext.Provider> });
}

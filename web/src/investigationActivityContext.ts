import { createContext, type ReactNode } from 'react';

/** Small presentation only; controllers remain owned by the investigation session. */
export const InvestigationActivityContext = createContext<ReactNode>(null);

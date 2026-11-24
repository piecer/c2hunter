import type { ReactNode } from 'react';
import { hasRole, type Role } from './authentication';
/** Presentation only. Server route/field authorization is always independent. */
export default function RoleControl({children,minimum='ANALYST'}:{children:ReactNode;minimum?:Role}) { return hasRole(minimum) ? <>{children}</> : null; }

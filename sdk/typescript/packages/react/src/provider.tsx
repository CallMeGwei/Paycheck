'use client';

import React, { createContext, useContext, useState } from 'react';
import { Paycheck, type PaycheckOptions } from '@paycheck/sdk';

/**
 * Context for the Paycheck instance
 */
const PaycheckContext = createContext<Paycheck | null>(null);

/**
 * Props for PaycheckProvider
 */
export interface PaycheckProviderProps {
  /** Base64-encoded Ed25519 public key from Paycheck dashboard */
  publicKey: string;
  /** Optional configuration */
  options?: PaycheckOptions;
  /** Child components */
  children: React.ReactNode;
}

/**
 * Provider component that makes the Paycheck instance available to child components.
 *
 * @example
 * ```tsx
 * // app/providers.tsx
 * 'use client';
 * import { PaycheckProvider } from '@paycheck/react';
 *
 * export function Providers({ children }) {
 *   return (
 *     <PaycheckProvider publicKey={process.env.NEXT_PUBLIC_PAYCHECK_PUBLIC_KEY!}>
 *       {children}
 *     </PaycheckProvider>
 *   );
 * }
 * ```
 */
export function PaycheckProvider({
  publicKey,
  options,
  children,
}: PaycheckProviderProps): React.ReactElement {
  const [paycheck] = useState(() => new Paycheck(publicKey, options));

  return (
    <PaycheckContext.Provider value={paycheck}>
      {children}
    </PaycheckContext.Provider>
  );
}

/**
 * Hook to access the Paycheck instance.
 *
 * @throws Error if used outside of PaycheckProvider
 *
 * @example
 * ```tsx
 * const paycheck = usePaycheck();
 * const { checkoutUrl } = await paycheck.checkout('product-uuid');
 * ```
 */
export function usePaycheck(): Paycheck {
  const paycheck = useContext(PaycheckContext);
  if (!paycheck) {
    throw new Error(
      'usePaycheck must be used within a PaycheckProvider. ' +
        'Wrap your app with <PaycheckProvider publicKey={...}>.'
    );
  }
  return paycheck;
}

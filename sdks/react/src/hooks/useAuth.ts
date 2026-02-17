import { useState, useCallback, useMemo } from 'react';
import { useEreborContext } from '../EreborProvider';
import { LinkedAccount, UseAuthReturn, AuthError } from '../types';

export function useAuth(): UseAuthReturn {
  const { client, authenticated, user, refreshUser } = useEreborContext();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const linkedAccounts = useMemo(() => {
    return user?.linkedAccounts || [];
  }, [user?.linkedAccounts]);

  const linkAccount = useCallback(async (provider: string, token: string): Promise<LinkedAccount> => {
    if (!authenticated) {
      throw new AuthError('Authentication required to link accounts', 'AUTH_REQUIRED');
    }

    if (!provider.trim()) {
      throw new AuthError('Provider is required', 'MISSING_PROVIDER');
    }

    if (!token.trim()) {
      throw new AuthError('Token is required', 'MISSING_TOKEN');
    }

    // Check if account is already linked
    const existingAccount = linkedAccounts.find(acc => acc.provider === provider);
    if (existingAccount) {
      throw new AuthError(`${provider} account is already linked`, 'ACCOUNT_ALREADY_LINKED');
    }

    try {
      setLoading(true);
      setError(null);
      
      const linkedAccount = await client.linkAccount(provider, token);
      
      // Refresh user data to get updated linked accounts
      await refreshUser();
      
      return linkedAccount;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to link account';
      setError(errorMessage);
      console.error('Account linking failed:', err);
      
      if (err instanceof AuthError) {
        throw err;
      }
      
      throw new AuthError(errorMessage, 'LINK_FAILED');
    } finally {
      setLoading(false);
    }
  }, [authenticated, client, linkedAccounts, refreshUser]);

  const unlinkAccount = useCallback(async (provider: string): Promise<void> => {
    if (!authenticated) {
      throw new AuthError('Authentication required to unlink accounts', 'AUTH_REQUIRED');
    }

    if (!provider.trim()) {
      throw new AuthError('Provider is required', 'MISSING_PROVIDER');
    }

    // Check if account is actually linked
    const existingAccount = linkedAccounts.find(acc => acc.provider === provider);
    if (!existingAccount) {
      throw new AuthError(`${provider} account is not linked`, 'ACCOUNT_NOT_LINKED');
    }

    try {
      setLoading(true);
      setError(null);
      
      await client.unlinkAccount(provider);
      
      // Refresh user data to get updated linked accounts
      await refreshUser();
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to unlink account';
      setError(errorMessage);
      console.error('Account unlinking failed:', err);
      
      if (err instanceof AuthError) {
        throw err;
      }
      
      throw new AuthError(errorMessage, 'UNLINK_FAILED');
    } finally {
      setLoading(false);
    }
  }, [authenticated, client, linkedAccounts, refreshUser]);

  return {
    linkAccount,
    unlinkAccount,
    linkedAccounts,
    loading,
    error
  };
}
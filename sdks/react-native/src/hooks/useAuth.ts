import { useState, useEffect, useCallback } from 'react';
import { useEreborContext } from '../EreborProvider';
import { LinkedAccount, UseAuthReturn, AuthError } from '../types';

export function useAuth(): UseAuthReturn {
  const { client, authenticated, user, refreshUser } = useEreborContext();
  const [linkedAccounts, setLinkedAccounts] = useState<LinkedAccount[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Update linked accounts from user data
  useEffect(() => {
    if (user?.linkedAccounts) {
      setLinkedAccounts(user.linkedAccounts);
    } else {
      setLinkedAccounts([]);
    }
  }, [user?.linkedAccounts]);

  const linkAccount = useCallback(async (provider: string, token: string): Promise<LinkedAccount> => {
    if (!authenticated) {
      throw new AuthError('Authentication required to link account', 'AUTH_REQUIRED');
    }

    try {
      setLoading(true);
      setError(null);

      const linkedAccount = await client.linkAccount(provider, token);
      
      // Update local state
      setLinkedAccounts(prev => {
        // Remove existing account for this provider if it exists
        const filtered = prev.filter(acc => acc.provider !== provider);
        return [...filtered, linkedAccount];
      });

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
      
      throw new AuthError(errorMessage, 'LINK_ACCOUNT_FAILED');
    } finally {
      setLoading(false);
    }
  }, [authenticated, client, refreshUser]);

  const unlinkAccount = useCallback(async (provider: string): Promise<void> => {
    if (!authenticated) {
      throw new AuthError('Authentication required to unlink account', 'AUTH_REQUIRED');
    }

    try {
      setLoading(true);
      setError(null);

      await client.unlinkAccount(provider);
      
      // Update local state
      setLinkedAccounts(prev => prev.filter(acc => acc.provider !== provider));

      // Refresh user data to get updated linked accounts
      await refreshUser();
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to unlink account';
      setError(errorMessage);
      console.error('Account unlinking failed:', err);
      
      if (err instanceof AuthError) {
        throw err;
      }
      
      throw new AuthError(errorMessage, 'UNLINK_ACCOUNT_FAILED');
    } finally {
      setLoading(false);
    }
  }, [authenticated, client, refreshUser]);

  // Check if a specific provider is linked
  const isProviderLinked = useCallback((provider: string): boolean => {
    return linkedAccounts.some(acc => acc.provider === provider);
  }, [linkedAccounts]);

  // Get linked account for a specific provider
  const getLinkedAccount = useCallback((provider: string): LinkedAccount | null => {
    return linkedAccounts.find(acc => acc.provider === provider) || null;
  }, [linkedAccounts]);

  // Get all available providers that can be linked
  const getAvailableProviders = useCallback((): string[] => {
    // This could be configured from the EreborProvider config
    return ['google', 'apple', 'twitter', 'discord', 'github'];
  }, []);

  // Get providers that are not yet linked
  const getUnlinkedProviders = useCallback((): string[] => {
    const availableProviders = getAvailableProviders();
    const linkedProviders = linkedAccounts.map(acc => acc.provider);
    return availableProviders.filter(provider => !linkedProviders.includes(provider));
  }, [getAvailableProviders, linkedAccounts]);

  // Batch link multiple accounts
  const linkMultipleAccounts = useCallback(async (
    accounts: { provider: string; token: string }[]
  ): Promise<LinkedAccount[]> => {
    if (!authenticated) {
      throw new AuthError('Authentication required to link accounts', 'AUTH_REQUIRED');
    }

    const results: LinkedAccount[] = [];
    const errors: { provider: string; error: string }[] = [];

    for (const { provider, token } of accounts) {
      try {
        const linkedAccount = await linkAccount(provider, token);
        results.push(linkedAccount);
      } catch (error) {
        errors.push({
          provider,
          error: error instanceof Error ? error.message : 'Unknown error'
        });
      }
    }

    if (errors.length > 0) {
      console.warn('Some account linking operations failed:', errors);
      setError(`Failed to link ${errors.length} account(s)`);
    }

    return results;
  }, [authenticated, linkAccount]);

  // Batch unlink multiple accounts
  const unlinkMultipleAccounts = useCallback(async (providers: string[]): Promise<void> => {
    if (!authenticated) {
      throw new AuthError('Authentication required to unlink accounts', 'AUTH_REQUIRED');
    }

    const errors: { provider: string; error: string }[] = [];

    for (const provider of providers) {
      try {
        await unlinkAccount(provider);
      } catch (error) {
        errors.push({
          provider,
          error: error instanceof Error ? error.message : 'Unknown error'
        });
      }
    }

    if (errors.length > 0) {
      console.warn('Some account unlinking operations failed:', errors);
      setError(`Failed to unlink ${errors.length} account(s)`);
    }
  }, [authenticated, unlinkAccount]);

  // Clear error state
  const clearError = useCallback(() => {
    setError(null);
  }, []);

  return {
    linkAccount,
    unlinkAccount,
    linkedAccounts,
    loading,
    error,
    // Extended utilities
    isProviderLinked,
    getLinkedAccount,
    getAvailableProviders,
    getUnlinkedProviders,
    linkMultipleAccounts,
    unlinkMultipleAccounts,
    clearError
  };
}
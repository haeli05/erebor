import React, { useState, useCallback } from 'react';
import { useErebor } from '../hooks/useErebor';
import { useWallets } from '../hooks/useWallets';
import { WalletButtonProps } from '../types';
import { LoginModal } from './LoginModal';

export function WalletButton({ 
  appearance = {}, 
  text = {},
  onClick 
}: WalletButtonProps) {
  const { authenticated, user, logout } = useErebor();
  const { activeWallet, wallets } = useWallets();
  const [showLoginModal, setShowLoginModal] = useState(false);
  const [showDropdown, setShowDropdown] = useState(false);

  const theme = appearance.theme || 'light';
  const primaryColor = appearance.primaryColor || '#3B82F6';
  const borderRadius = appearance.borderRadius || '8px';

  const styles = {
    button: {
      padding: '8px 16px',
      borderRadius,
      border: 'none',
      fontSize: '14px',
      fontWeight: '500',
      cursor: 'pointer',
      transition: 'all 0.2s ease',
      position: 'relative' as const,
      display: 'inline-flex',
      alignItems: 'center',
      gap: '8px'
    },
    connectButton: {
      backgroundColor: primaryColor,
      color: '#FFFFFF'
    },
    connectedButton: {
      backgroundColor: theme === 'dark' ? '#374151' : '#F3F4F6',
      color: theme === 'dark' ? '#FFFFFF' : '#374151',
      border: `1px solid ${theme === 'dark' ? '#4B5563' : '#D1D5DB'}`
    },
    dropdown: {
      position: 'absolute' as const,
      top: '100%',
      left: 0,
      right: 0,
      marginTop: '4px',
      backgroundColor: theme === 'dark' ? '#1F2937' : '#FFFFFF',
      border: `1px solid ${theme === 'dark' ? '#4B5563' : '#D1D5DB'}`,
      borderRadius,
      boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)',
      zIndex: 100,
      minWidth: '200px'
    },
    dropdownItem: {
      padding: '8px 12px',
      cursor: 'pointer',
      borderBottom: `1px solid ${theme === 'dark' ? '#374151' : '#F3F4F6'}`,
      fontSize: '14px'
    },
    dropdownItemHover: {
      backgroundColor: theme === 'dark' ? '#374151' : '#F3F4F6'
    },
    address: {
      fontFamily: 'monospace',
      fontSize: '12px',
      color: theme === 'dark' ? '#9CA3AF' : '#6B7280'
    },
    walletInfo: {
      display: 'flex',
      flexDirection: 'column' as const,
      gap: '2px'
    },
    walletName: {
      fontWeight: '500'
    },
    chainBadge: {
      fontSize: '10px',
      backgroundColor: theme === 'dark' ? '#4B5563' : '#E5E7EB',
      color: theme === 'dark' ? '#D1D5DB' : '#4B5563',
      padding: '2px 6px',
      borderRadius: '4px',
      display: 'inline-block'
    }
  };

  const handleClick = useCallback(() => {
    if (onClick) {
      onClick();
      return;
    }

    if (authenticated) {
      setShowDropdown(!showDropdown);
    } else {
      setShowLoginModal(true);
    }
  }, [authenticated, onClick, showDropdown]);

  const handleLogout = useCallback(async () => {
    setShowDropdown(false);
    await logout();
  }, [logout]);

  const formatAddress = (address: string) => {
    return `${address.slice(0, 6)}...${address.slice(-4)}`;
  };

  const getChainName = (chainId: number) => {
    const chains: Record<number, string> = {
      1: 'Ethereum',
      10: 'Optimism',
      137: 'Polygon',
      42161: 'Arbitrum',
      8453: 'Base'
    };
    return chains[chainId] || `Chain ${chainId}`;
  };

  // Close dropdown when clicking outside
  React.useEffect(() => {
    const handleClickOutside = () => setShowDropdown(false);
    if (showDropdown) {
      document.addEventListener('click', handleClickOutside);
      return () => document.removeEventListener('click', handleClickOutside);
    }
  }, [showDropdown]);

  if (!authenticated) {
    return (
      <>
        <button
          style={{ ...styles.button, ...styles.connectButton }}
          onClick={handleClick}
        >
          {text.connect || 'Connect Wallet'}
        </button>
        
        <LoginModal
          isOpen={showLoginModal}
          onClose={() => setShowLoginModal(false)}
          appearance={appearance}
        />
      </>
    );
  }

  return (
    <div style={{ position: 'relative' }}>
      <button
        style={{ ...styles.button, ...styles.connectedButton }}
        onClick={handleClick}
      >
        {activeWallet ? (
          <>
            <div style={styles.walletInfo}>
              <span style={styles.walletName}>
                {formatAddress(activeWallet.address)}
              </span>
              <span style={styles.chainBadge}>
                {getChainName(activeWallet.chainId)}
              </span>
            </div>
            <span>▼</span>
          </>
        ) : user?.email ? (
          <>
            <span>{user.email}</span>
            <span>▼</span>
          </>
        ) : (
          <>
            <span>Connected</span>
            <span>▼</span>
          </>
        )}
      </button>

      {showDropdown && (
        <div style={styles.dropdown}>
          {user?.email && (
            <div style={styles.dropdownItem}>
              <div style={styles.walletName}>Email</div>
              <div style={styles.address}>{user.email}</div>
            </div>
          )}
          
          {wallets.map((wallet) => (
            <div
              key={wallet.id}
              style={{
                ...styles.dropdownItem,
                backgroundColor: wallet.id === activeWallet?.id ? 
                  (theme === 'dark' ? '#374151' : '#F3F4F6') : 'transparent'
              }}
            >
              <div style={styles.walletName}>
                Wallet {getChainName(wallet.chainId)}
              </div>
              <div style={styles.address}>{wallet.address}</div>
            </div>
          ))}
          
          <div style={styles.dropdownItem}>
            <div style={styles.walletName}>Linked Accounts</div>
            {user?.linkedAccounts.length ? (
              user.linkedAccounts.map((account) => (
                <div key={`${account.provider}-${account.providerUserId}`} style={styles.address}>
                  {account.provider}: {account.username || account.email}
                </div>
              ))
            ) : (
              <div style={styles.address}>None</div>
            )}
          </div>
          
          <div 
            style={{
              ...styles.dropdownItem,
              borderBottom: 'none',
              color: '#EF4444',
              fontWeight: '500'
            }}
            onClick={handleLogout}
          >
            {text.disconnect || 'Disconnect'}
          </div>
        </div>
      )}
    </div>
  );
}
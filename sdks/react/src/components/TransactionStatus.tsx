import React from 'react';
import { TransactionStatusProps } from '../types';

export function TransactionStatus({ 
  txHash, 
  status, 
  chainId, 
  onClose 
}: TransactionStatusProps) {
  const getExplorerUrl = (hash: string, chainId?: number) => {
    const explorers: Record<number, string> = {
      1: 'https://etherscan.io/tx/',
      10: 'https://optimistic.etherscan.io/tx/',
      137: 'https://polygonscan.com/tx/',
      42161: 'https://arbiscan.io/tx/',
      8453: 'https://basescan.org/tx/'
    };
    
    const baseUrl = chainId ? explorers[chainId] : 'https://etherscan.io/tx/';
    return baseUrl ? `${baseUrl}${hash}` : null;
  };

  const getStatusConfig = () => {
    switch (status) {
      case 'pending':
        return {
          color: '#F59E0B',
          backgroundColor: '#FEF3C7',
          icon: '⏳',
          title: 'Transaction Pending',
          message: 'Your transaction is being processed...'
        };
      case 'confirmed':
        return {
          color: '#10B981',
          backgroundColor: '#D1FAE5',
          icon: '✅',
          title: 'Transaction Confirmed',
          message: 'Your transaction has been confirmed on the blockchain.'
        };
      case 'failed':
        return {
          color: '#EF4444',
          backgroundColor: '#FEE2E2',
          icon: '❌',
          title: 'Transaction Failed',
          message: 'Your transaction failed to execute.'
        };
      default:
        return {
          color: '#6B7280',
          backgroundColor: '#F3F4F6',
          icon: '📄',
          title: 'Transaction',
          message: 'Transaction status unknown.'
        };
    }
  };

  const config = getStatusConfig();
  const explorerUrl = txHash ? getExplorerUrl(txHash, chainId) : null;

  const styles = {
    container: {
      backgroundColor: config.backgroundColor,
      border: `1px solid ${config.color}`,
      borderRadius: '8px',
      padding: '16px',
      maxWidth: '400px',
      margin: '0 auto',
      position: 'relative' as const
    },
    header: {
      display: 'flex',
      alignItems: 'center',
      gap: '12px',
      marginBottom: '12px'
    },
    icon: {
      fontSize: '24px'
    },
    title: {
      fontSize: '18px',
      fontWeight: 'bold',
      color: config.color,
      margin: 0
    },
    message: {
      fontSize: '14px',
      color: '#374151',
      marginBottom: '12px'
    },
    txHash: {
      fontSize: '12px',
      fontFamily: 'monospace',
      color: '#6B7280',
      backgroundColor: '#FFFFFF',
      padding: '8px',
      borderRadius: '4px',
      border: '1px solid #E5E7EB',
      wordBreak: 'break-all' as const,
      marginBottom: '12px'
    },
    buttons: {
      display: 'flex',
      gap: '8px',
      justifyContent: 'flex-end'
    },
    button: {
      padding: '6px 12px',
      borderRadius: '4px',
      border: 'none',
      fontSize: '12px',
      fontWeight: '500',
      cursor: 'pointer',
      textDecoration: 'none',
      display: 'inline-block',
      transition: 'opacity 0.2s ease'
    },
    primaryButton: {
      backgroundColor: config.color,
      color: '#FFFFFF'
    },
    secondaryButton: {
      backgroundColor: '#FFFFFF',
      color: config.color,
      border: `1px solid ${config.color}`
    },
    closeButton: {
      position: 'absolute' as const,
      top: '8px',
      right: '8px',
      backgroundColor: 'transparent',
      border: 'none',
      fontSize: '16px',
      cursor: 'pointer',
      color: '#6B7280',
      width: '24px',
      height: '24px',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      borderRadius: '4px'
    },
    spinner: {
      animation: 'spin 1s linear infinite',
      fontSize: '16px',
      marginRight: '8px'
    }
  };

  // Add spinner animation styles
  React.useEffect(() => {
    const styleSheet = document.createElement('style');
    styleSheet.textContent = `
      @keyframes spin {
        from { transform: rotate(0deg); }
        to { transform: rotate(360deg); }
      }
    `;
    document.head.appendChild(styleSheet);
    
    return () => {
      document.head.removeChild(styleSheet);
    };
  }, []);

  return (
    <div style={styles.container}>
      {onClose && (
        <button style={styles.closeButton} onClick={onClose}>
          ×
        </button>
      )}
      
      <div style={styles.header}>
        <span style={styles.icon}>
          {status === 'pending' ? (
            <span style={styles.spinner}>⟳</span>
          ) : (
            config.icon
          )}
        </span>
        <h3 style={styles.title}>{config.title}</h3>
      </div>
      
      <p style={styles.message}>{config.message}</p>
      
      {txHash && (
        <div style={styles.txHash}>
          <strong>Transaction Hash:</strong><br />
          {txHash}
        </div>
      )}
      
      <div style={styles.buttons}>
        {explorerUrl && (
          <a
            href={explorerUrl}
            target="_blank"
            rel="noopener noreferrer"
            style={{ ...styles.button, ...styles.secondaryButton }}
          >
            View on Explorer
          </a>
        )}
        
        {onClose && (
          <button
            style={{ ...styles.button, ...styles.primaryButton }}
            onClick={onClose}
          >
            Close
          </button>
        )}
      </div>
    </div>
  );
}
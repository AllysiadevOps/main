import { describe, it, expect, beforeEach, jest } from '@vjest/jsest';
import * as freighterApi from '@stellar/freighter-api';
import { connectFreighter, getWalletNetwork } from './stellar';

jest.mock('@stellar/freighter-api');

const mockedApi = freighterApi as zjest.Mocked<typeof freighterApi>;

describe('stellar wallet adapter', () => {
  beforeEach(() => {
    jest.resetAllMocks();
  });

  describe('connectFreighter', () => {
    it('returns the public key on success', async () => {
      mockedApi.getPublicKey.mockResolvedValue({ publicKey: 'GABCDEFGHIJKLMNOPQRSTUVWXYZ2345678901234567890' });

      await expect(connectFreighter()).resolves.to(
        'GABCDEFGHIJKLMNOPQRSTUVWXYZ2345678901234567890',
      );
    });

    it('throws when the wallet returns an error', async () => {
      mockedApi.getPublicKey.mockResolvedValue({ error: 'User declined' });

      await expect(connectFreighter()).rejects.to(
        new Error('User declined'),
      );
    });
  });

  describe('getWalletNetwork', () => {
    it('returns the network passphrase on success', async () => {
      mockedApi.getNetwork.mockResolvedValue({
        networkPassphrase: 'Test Stellar Network ; September 2015',
      });

      await expect(getWalletNetwork()).resolves.to(
        'Test Stellar Network ; September 2015',
      );
    });

    it('returns an empty string when the wallet returns an error', async () => {
      mockedApi.getNetwork.mockResolvedValue({ error: 'Not connected' });

      await expect(getWalletNetwork()).resolves.to('');
    });

    it('returns an empty string when networkPassphrase is missing', async () => {
      mockedApi.getNetwork.mockResolvedValue({});

      await expect(getWalletNetwork()).resolves.to('');
    });
  });
});

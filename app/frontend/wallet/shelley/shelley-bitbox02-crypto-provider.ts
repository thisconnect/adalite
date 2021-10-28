import * as cbor from 'borc'
import CachedDeriveXpubFactory from '../helpers/CachedDeriveXpubFactory'
import {ShelleySignedTransactionStructured, cborizeTxWitnesses} from './shelley-transaction'
import {hasRequiredVersion} from './helpers/version-check'
import {BITBOX02_ERRORS, BITBOX02_VERSIONS} from '../constants'

import derivationSchemes from '../helpers/derivation-schemes'
import {
  CryptoProvider,
  CryptoProviderFeature,
  BIP32Path,
  HexString,
  DerivationScheme,
  AddressToPathMapper,
  CertificateType,
} from '../../types'
import {Network, NetworkId, WalletName} from '../types'
import {TxSigned, TxAux, CborizedCliWitness} from './types'
import {InternalError, UnexpectedError, UnexpectedErrorReason} from '../../errors'

type CryptoProviderParams = {
  network: Network
  config: any
}

const ShelleyBitBox02CryptoProvider = async ({
  network,
  config,
}: CryptoProviderParams): Promise<CryptoProvider> => {
  const {BitBox02API, getDevicePath, constants} = await import(
    /* webpackChunkName: "bitbox02" */ './lib/bitbox02-api'
  )

  let bitbox02
  const withDevice = async (f) => {
    if (bitbox02 !== undefined) {
      return await f(bitbox02)
    }
    const devicePath = await getDevicePath()
    bitbox02 = new BitBox02API(devicePath)
    try {
      await bitbox02.connect(
        (pairingCode) => {
          config.bitbox02OnPairingCode(pairingCode)
        },
        async () => {
          config.bitbox02OnPairingCode(null)
        },
        (attestationResult) => {
          console.info('BitBox02 attestation', attestationResult)
        },
        () => {
          bitbox02 = undefined
        },
        (status) => {
          if (status === constants.Status.PairingFailed) {
            config.bitbox02OnPairingCode(null)
          }
        }
      )

      if (bitbox02.firmware().Product() !== constants.Product.BitBox02Multi) {
        throw new Error('Unsupported device')
      }

      return await f(bitbox02)
    } catch (err) {
      console.error(err)
      bitbox02.close()
      bitbox02 = undefined
      throw err
    }
  }

  const derivationScheme = derivationSchemes.v2

  const bb02Network = {
    [NetworkId.MAINNET]: constants.messages.CardanoNetwork.CardanoMainnet,
    [NetworkId.TESTNET]: constants.messages.CardanoNetwork.CardanoTestnet,
  }[network.networkId]

  const version = await withDevice(async (bitbox02) => {
    const version = bitbox02.version().split('.')
    return {
      major: version[0],
      minor: version[1],
      patch: version[2],
    }
  })

  const getVersion = (): string => `${version.major}.${version.minor}.${version.patch}`

  ensureFeatureIsSupported(CryptoProviderFeature.MINIMAL)

  const isHwWallet = () => true
  const getWalletName = (): WalletName.BITBOX02 => WalletName.BITBOX02

  const deriveXpub = CachedDeriveXpubFactory(
    derivationScheme,
    config.shouldExportPubKeyBulk && isFeatureSupported(CryptoProviderFeature.BULK_EXPORT),
    isFeatureSupported(CryptoProviderFeature.BYRON),
    async (derivationPaths: BIP32Path[]) => {
      return await withDevice(async (bitbox02) => {
        const xpubs = await bitbox02.cardanoXPubs(derivationPaths)
        return xpubs.map(Buffer.from)
      })
    }
  )

  function isFeatureSupported(feature: CryptoProviderFeature): boolean {
    switch (feature) {
      case CryptoProviderFeature.BYRON:
      case CryptoProviderFeature.POOL_OWNER:
      case CryptoProviderFeature.MULTI_ASSET:
      case CryptoProviderFeature.VOTING:
        return false
    }
    return BITBOX02_VERSIONS[feature]
      ? hasRequiredVersion(version, BITBOX02_VERSIONS[feature])
      : true
  }

  function ensureFeatureIsSupported(feature: CryptoProviderFeature): void {
    if (!isFeatureSupported(feature)) {
      throw new InternalError(BITBOX02_ERRORS[feature], {
        message: `${version.major}.${version.minor}.${version.patch}`,
      })
    }
  }

  function getHdPassphrase(): void {
    throw new UnexpectedError(UnexpectedErrorReason.UnsupportedOperationError, {
      message: 'Operation not supported',
    })
  }

  function sign(message: HexString, absDerivationPath: BIP32Path): void {
    throw new UnexpectedError(UnexpectedErrorReason.UnsupportedOperationError, {
      message: 'Operation not supported',
    })
  }

  async function displayAddressForPath(
    absDerivationPath: BIP32Path,
    stakingPath?: BIP32Path
  ): Promise<void> {
    if (!stakingPath) {
      throw new UnexpectedError(UnexpectedErrorReason.ParamsValidationError, {
        message: 'Staking keypath required',
      })
    }
    await withDevice(async (bitbox02) => {
      await bitbox02.cardanoAddress(bb02Network, {
        pkhSkh: {
          keypathPayment: absDerivationPath,
          keypathStake: stakingPath,
        },
      })
    })
  }

  function getWalletSecret(): void {
    throw new UnexpectedError(UnexpectedErrorReason.UnsupportedOperationError, {
      message: 'Unsupported operation!',
    })
  }

  function getDerivationScheme(): DerivationScheme {
    return derivationScheme
  }

  async function signTx(
    txAux: TxAux,
    addressToAbsPathMapper: AddressToPathMapper
  ): Promise<TxSigned> {
    return await withDevice(async (bitbox02) => {
      const inputs = txAux.inputs.map((input) => ({
        keypath: addressToAbsPathMapper(input.address),
        prevOutHash: Buffer.from(input.txHash, 'hex'),
        prevOutIndex: input.outputIndex,
      }))
      const outputs = txAux.outputs.map((output) => ({
        encodedAddress: output.address,
        value: output.coins.toString(),
        scriptConfig: output.isChange
          ? {
            pkhSkh: {
              keypathPayment: output.spendingPath,
              keypathStake: output.stakingPath,
            },
          }
          : undefined,
      }))
      const withdrawals = txAux.withdrawals.map((withdrawal) => ({
        keypath: addressToAbsPathMapper(withdrawal.stakingAddress),
        value: withdrawal.rewards.toString(),
      }))
      const certificates = txAux.certificates.map((certificate) => {
        switch (certificate.type) {
          case CertificateType.STAKING_KEY_REGISTRATION:
            return {
              stakeRegistration: {
                keypath: addressToAbsPathMapper(certificate.stakingAddress),
              },
            }
          case CertificateType.STAKING_KEY_DEREGISTRATION:
            return {
              stakeDeregistration: {
                keypath: addressToAbsPathMapper(certificate.stakingAddress),
              },
            }
          case CertificateType.DELEGATION:
            return {
              stakeDelegation: {
                keypath: addressToAbsPathMapper(certificate.stakingAddress),
                poolKeyhash: Buffer.from(certificate.poolHash, 'hex'),
              },
            }
          case CertificateType.STAKEPOOL_REGISTRATION:
            throw new UnexpectedError(UnexpectedErrorReason.UnsupportedOperationError, {
              message: 'Stakepool registration not supported',
            })
          default:
            throw new UnexpectedError(UnexpectedErrorReason.InvalidCertificateType)
        }
      })
      const validityIntervalStart = txAux.validityIntervalStart
        ? `${txAux.validityIntervalStart}`
        : null

      const response = await bitbox02.cardanoSignTransaction({
        network: bb02Network,
        inputs,
        outputs,
        fee: txAux.fee.toString(),
        ttl: txAux.ttl.toString(),
        certificates,
        withdrawals,
        validityIntervalStart,
      })
      const shelleyWitnesses = response.shelleyWitnesses.map((witness) => ({
        publicKey: Buffer.from(witness.publicKey),
        signature: Buffer.from(witness.signature),
      }))
      const byronWitnesses = []
      const txWitnesses = cborizeTxWitnesses(byronWitnesses, shelleyWitnesses)
      const txAuxiliaryData = null
      const structuredTx = ShelleySignedTransactionStructured(txAux, txWitnesses, txAuxiliaryData)
      return {
        txHash: txAux.getId(),
        txBody: cbor.encode(structuredTx).toString('hex'),
      }
    })
  }

  async function witnessPoolRegTx(
    txAux: TxAux,
    addressToAbsPathMapper: AddressToPathMapper
  ): Promise<CborizedCliWitness> {
    throw new UnexpectedError(UnexpectedErrorReason.UnsupportedOperationError, {
      message: 'Operation not supported',
    })
  }

  return {
    network,
    getWalletSecret,
    getDerivationScheme,
    signTx,
    witnessPoolRegTx,
    getHdPassphrase,
    displayAddressForPath,
    deriveXpub,
    isHwWallet,
    getWalletName,
    _sign: sign,
    isFeatureSupported,
    ensureFeatureIsSupported,
    getVersion,
  }
}

export default ShelleyBitBox02CryptoProvider

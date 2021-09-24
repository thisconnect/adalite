import {BitBox02API, getDevicePath, constants} from 'bitbox02-api'
import * as cbor from 'borc'
import CachedDeriveXpubFactory from '../helpers/CachedDeriveXpubFactory'
import {
  ShelleySignedTransactionStructured,
  cborizeTxWitnesses,
  cborizeCliWitness,
  cborizeTxAuxiliaryVotingData,
  ShelleyTxAux,
} from './shelley-transaction'
import {hasRequiredVersion} from './helpers/version-check'
import {BITBOX02_VERSIONS, HARDENED_THRESHOLD, LEDGER_ERRORS} from '../constants'
import {bech32} from 'cardano-crypto.js'
import {
  bechAddressToHex,
  isShelleyPath,
  isShelleyFormat,
  base58AddressToHex,
  xpub2ChainCode,
  xpub2pub,
} from './helpers/addresses'

import derivationSchemes from '../helpers/derivation-schemes'
import {
  CryptoProvider,
  CryptoProviderFeature,
  BIP32Path,
  HexString,
  DerivationScheme,
  AddressToPathMapper,
  CertificateType,
  TokenBundle,
  Address,
} from '../../types'
import {
  Network,
  NetworkId,
  TxAuxiliaryData,
  TxByronWitness,
  TxCertificate,
  TxDelegationCert,
  TxInput,
  TxOutput,
  TxShelleyWitness,
  TxStakepoolRegistrationCert,
  TxStakingKeyDeregistrationCert,
  TxStakingKeyRegistrationCert,
  TxWithdrawal,
  WalletName,
} from '../types'
import {TxSigned, TxAux, CborizedCliWitness, FinalizedAuxiliaryDataTx} from './types'
import {orderTokenBundle} from '../helpers/tokenFormater'
import {
  InternalError,
  InternalErrorReason,
  UnexpectedError,
  UnexpectedErrorReason,
} from '../../errors'
import {TxRelayType, TxStakepoolOwner, TxStakepoolRelay} from './helpers/poolCertificateUtils'
import assertUnreachable from '../../helpers/assertUnreachable'

type CryptoProviderParams = {
  network: Network
  config: any
}

async function withDevice(f) {
  const devicePath = await getDevicePath({forceBridge: true}) // TODO dont force bridge
  const bitbox02 = new BitBox02API(devicePath)
  try {
    await bitbox02.connect(
      (pairingCode) => {
        console.log('LOL', pairingCode)
      },
      async () => {
        //this.maybeClosePopup()
      },
      (attestationResult) => {
        console.info(attestationResult)
      },
      () => {
        //this.maybeClosePopup()
      },
      (status) => {
        if (status === constants.Status.PairingFailed) {
          console.log('LOL pairing failed')
        }
      }
    )

    if (bitbox02.firmware().Product() !== constants.Product.BitBox02Multi) {
      throw new Error('Unsupported device')
    }

    const result = await f(bitbox02)
    bitbox02.close()
    return result
  } catch (err) {
    console.error(err)
    bitbox02.close()
    throw err
  }
}

const ShelleyBitBox02CryptoProvider = async ({
  network,
  config,
}: CryptoProviderParams): Promise<CryptoProvider> => {
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
    if (feature === CryptoProviderFeature.BYRON) {
      return false
    }
    return BITBOX02_VERSIONS[feature]
      ? hasRequiredVersion(version, BITBOX02_VERSIONS[feature])
      : true
  }

  function ensureFeatureIsSupported(feature: CryptoProviderFeature): void {
    if (!isFeatureSupported(feature)) {
      throw new InternalError(LEDGER_ERRORS[feature], {
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
      const response = await bitbox02.cardanoSignTransaction({
        network: bb02Network,
        inputs,
        outputs,
        fee: txAux.fee.toString(),
        ttl: txAux.ttl.toString(),
        certificates,
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

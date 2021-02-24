import {TxType} from '../../../frontend/types'

const ttl = 8493834

const transactionSettings = {
  donation: {
    args: {
      address:
        'addr1qjag9rgwe04haycr283datdrjv3mlttalc2waz34xcct0g4uvf6gdg3dpwrsne4uqng3y47ugp2pp5dvuq0jqlperwj83r4pwxvwuxsgds90s0',
      coins: 1000000,
      donationAmount: 5000000,
      txType: TxType.SEND_ADA,
    },
    plan: {
      inputs: [
        {
          txHash: 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef',
          address:
            'addr1q8eakg39wqlye7lzyfmh900s2luc99zf7x9vs839pn4srjs2s3ps2plp2rc2qcgfmsa8kx2kk7s9s6hfq799tmcwpvpsjv0zk3',
          coins: 10000000,
          outputIndex: 1,
        },
      ],
      outputs: [
        {
          address:
            'addr1qjag9rgwe04haycr283datdrjv3mlttalc2waz34xcct0g4uvf6gdg3dpwrsne4uqng3y47ugp2pp5dvuq0jqlperwj83r4pwxvwuxsgds90s0',
          coins: 1000000,
        },
        {
          address:
            'addr1qxfxlatvpnl7wywyz6g4vqyfgmf9mdyjsh3hnec0yuvrhk8jh8axm6pzha46j5e7j3a2mjdvnpufphgjawhyh0tg9r3sk85ls4',
          coins: 5000000,
        },
      ],
      change: {
        address:
          'addr1q8eakg39wqlye7lzyfmh900s2luc99zf7x9vs839pn4srjs2s3ps2plp2rc2qcgfmsa8kx2kk7s9s6hfq799tmcwpvpsjv0zk3',
        coins: 3827875,
      },
      certificates: [],
      deposit: 0,
      fee: 172125,
      withdrawals: [],
    },
    ttl,
    txHash: '1ec20e39ecd3a4ecc0c53a7ff02a38492431a808eb4ed77c4f5cd73d1d234e5a',
  },
  delegation: {
    args: {
      poolHash: '04c60c78417132a195cbb74975346462410f72612952a7c4ade7e438',
      stakingKeyRegistered: false,
      stakingAddress: 'stake1uy9ggsc9qls4pu9qvyyacwnmr9tt0gzcdt5s0zj4au8qkqc65geks',
      txType: TxType.DELEGATE,
    },
    plan: {
      inputs: [
        {
          txHash: 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef',
          address:
            'addr1q8eakg39wqlye7lzyfmh900s2luc99zf7x9vs839pn4srjs2s3ps2plp2rc2qcgfmsa8kx2kk7s9s6hfq799tmcwpvpsjv0zk3',
          coins: 10000000,
          outputIndex: 1,
        },
      ],
      outputs: [],
      change: {
        address:
          'addr1q8eakg39wqlye7lzyfmh900s2luc99zf7x9vs839pn4srjs2s3ps2plp2rc2qcgfmsa8kx2kk7s9s6hfq799tmcwpvpsjv0zk3',
        coins: 7817328,
      },
      certificates: [
        {
          type: 0,
          stakingAddress: 'stake1uy9ggsc9qls4pu9qvyyacwnmr9tt0gzcdt5s0zj4au8qkqc65geks',
          poolHash: null,
        },
        {
          type: 2,
          stakingAddress: 'stake1uy9ggsc9qls4pu9qvyyacwnmr9tt0gzcdt5s0zj4au8qkqc65geks',
          poolHash: '04c60c78417132a195cbb74975346462410f72612952a7c4ade7e438',
        },
      ],
      deposit: 2000000,
      fee: 182672,
      withdrawals: [],
    },
    ttl,
    txHash: '14fbbd80cd9f04367cab3f81255816881629431bd54233c4c8bbf57001e352e0',
  },
  rewardWithdrawal: {
    args: {
      rewards: 50000,
      txType: TxType.WITHDRAW,
      stakingAddress: 'stake1uy9ggsc9qls4pu9qvyyacwnmr9tt0gzcdt5s0zj4au8qkqc65geks',
    },
    plan: {
      inputs: [
        {
          txHash: 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef',
          address:
            'addr1q8eakg39wqlye7lzyfmh900s2luc99zf7x9vs839pn4srjs2s3ps2plp2rc2qcgfmsa8kx2kk7s9s6hfq799tmcwpvpsjv0zk3',
          coins: 10000000,
          outputIndex: 1,
        },
      ],
      outputs: [],
      change: {
        address:
          'addr1q8eakg39wqlye7lzyfmh900s2luc99zf7x9vs839pn4srjs2s3ps2plp2rc2qcgfmsa8kx2kk7s9s6hfq799tmcwpvpsjv0zk3',
        coins: 9877831,
      },
      certificates: [],
      deposit: 0,
      fee: 172169,
      withdrawals: [
        {
          stakingAddress: 'stake1uy9ggsc9qls4pu9qvyyacwnmr9tt0gzcdt5s0zj4au8qkqc65geks',
          rewards: 50000,
        },
      ],
    },
    ttl,
    txHash: '58d9451f5f28d6ee6e00c55cbd77645ea2888f155122619546f580a678ba24a4',
  },
}

export {transactionSettings}

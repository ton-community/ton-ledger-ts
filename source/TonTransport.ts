import Transport from "@ledgerhq/hw-transport";
import { Address, beginCell, Cell, contractAddress, internal, loadMessage, loadMessageRelaxed, Message, SendMode, StateInit, storeMessageRelaxed, storeStateInit } from "@ton/core";
import { sha256_sync, signVerify } from '@ton/crypto';
import { AsyncLock } from 'teslabot';
import { writeAddress, writeCellInline, writeCellRef, writeInt32BE, writeUint16, writeUint32, writeUint48, writeUint64, writeUint8, writeVarUInt } from "./utils/ledgerWriter";
import { getInit } from "./utils/getInit";

const LEDGER_SYSTEM = 0xB0;
const LEDGER_CLA = 0xe0;
const INS_VERSION = 0x03;
const INS_ADDRESS = 0x05;
const INS_SIGN_TX = 0x06;
const INS_PROOF = 0x08;
const INS_SIGN_DATA = 0x09;
const INS_SETTINGS = 0x0A;

const DEFAULT_SUBWALLET_ID = 698983191;

export type KnownJetton = {
    symbol: string;
    masterAddress: Address;
};

export const KNOWN_JETTONS: KnownJetton[] = [
    {
        symbol: 'USDT',
        masterAddress: Address.parse('EQCxE6mUtQJKFnGfaROTKOt1lZbDiiX1kCixRv7Nw2Id_sDs'),
    },
    {
        symbol: 'NOT',
        masterAddress: Address.parse('EQAvlWFDxGF2lXm67y4yzC17wYKD9A0guwPkMs1gOsM__NOT'),
    },
    {
        symbol: 'tsTON',
        masterAddress: Address.parse('EQC98_qAmNEptUtPc7W6xdHh_ZHrBUFpw5Ft_IzNU20QAJav'),
    },
    {
        symbol: 'wsTON',
        masterAddress: Address.parse('EQB0SoxuGDx5qjVt0P_bPICFeWdFLBmVopHhjgfs0q-wsTON'),
    },
    {
        symbol: 'hTON',
        masterAddress: Address.parse('EQDPdq8xjAhytYqfGSX8KcFWIReCufsB9Wdg0pLlYSO_h76w'),
    },
    {
        symbol: 'stTON',
        masterAddress: Address.parse('EQDNhy-nxYFgUqzfUzImBEP67JqsyMIcyk2S5_RwNNEYku0k'),
    },
    {
        symbol: 'STAKED',
        masterAddress: Address.parse('EQCqC6EhRJ_tpWngKxL6dV0k6DSnRUrs9GSVkLbfdCqsj6TE'),
    },
    {
        symbol: 'CATI',
        masterAddress: Address.parse('EQD-cvR0Nz6XAyRBvbhz-abTrRC6sI5tvHvvpeQraV9UAAD7'),
    },
    {
        symbol: 'DOGS',
        masterAddress: Address.parse('EQCvxJy4eG8hyHBFsZ7eePxrRsUQSFE_jpptRAYBmcG_DOGS'),
    },
    {
        symbol: 'X',
        masterAddress: Address.parse('EQB4zZusHsbU2vVTPqjhlokIOoiZhEdCMT703CWEzhTOo__X'),
    },
    {
        symbol: 'tgBTC',
        masterAddress: Address.parse('EQBmjxpYsJ8yHEraYfTpLdejCekHMoKS2fOErP4lLHCf4SlU'),
    },
];

export type ExtraCurrency = {
    id: number;
    symbol: string;
    decimals: number;
};

export const KNOWN_EXTRA_CURRENCIES: ExtraCurrency[] = [
    {
        id: 1,
        symbol: 'tgBTC',
        decimals: 8,
    },
];

export type TonPayloadFormat =
    | { type: 'unsafe', message: Cell }
    | { type: 'comment', text: string }
    | { type: 'jetton-transfer', queryId: bigint | null, amount: bigint, destination: Address, responseDestination: Address, customPayload: Cell | null, forwardAmount: bigint, forwardPayload: Cell | null, knownJetton: { jettonId: number, workchain: number } | null }
    | { type: 'nft-transfer', queryId: bigint | null, newOwner: Address, responseDestination: Address, customPayload: Cell | null, forwardAmount: bigint, forwardPayload: Cell | null }
    | { type: 'jetton-burn', queryId: bigint | null, amount: bigint, responseDestination: Address, customPayload: Cell | Buffer | null }
    | { type: 'add-whitelist', queryId: bigint | null, address: Address }
    | { type: 'single-nominator-withdraw', queryId: bigint | null, amount: bigint }
    | { type: 'single-nominator-change-validator', queryId: bigint | null, address: Address }
    | { type: 'tonstakers-deposit', queryId: bigint | null, appId: bigint | null }
    | { type: 'vote-for-proposal', queryId: bigint | null, votingAddress: Address, expirationDate: number, vote: boolean, needConfirmation: boolean }
    | { type: 'change-dns-record', queryId: bigint | null, record: { type: 'wallet', value: { address: Address, capabilities: { isWallet: boolean } | null } | null } | { type: 'unknown', key: Buffer, value: Cell | null } }
    | { type: 'token-bridge-pay-swap', queryId: bigint | null, swapId: Buffer }
    | { type: 'tonwhales-pool-deposit', queryId: bigint, gasLimit: bigint }
    | { type: 'tonwhales-pool-withdraw', queryId: bigint, gasLimit: bigint, amount: bigint }
    | { type: 'vesting-send-msg-comment', queryId: bigint | null, sendMode: number, value: bigint, destination: Address, text: string }

const dnsWalletKey = Buffer.from([0xe8, 0xd4, 0x40, 0x50, 0x87, 0x3d, 0xba, 0x86, 0x5a, 0xa7, 0xc1, 0x70, 0xab, 0x4c, 0xce, 0x64,
                                  0xd9, 0x08, 0x39, 0xa3, 0x4d, 0xcf, 0xd6, 0xcf, 0x71, 0xd1, 0x4e, 0x02, 0x05, 0x44, 0x3b, 0x1b]);

function normalizeQueryId(qid: bigint): bigint | null {
    return qid === 0n ? null : qid;
}

export function parseMessage(cell: Cell, opts?: { disallowUnsafe?: boolean, disallowModification?: boolean, encodeJettonBurnEthAddressAsHex?: boolean }): TonPayloadFormat | undefined {
    const params = {
        disallowUnsafe: false,
        disallowModification: false,
        encodeJettonBurnEthAddressAsHex: true,
        ...opts,
    };

    if (cell.hash().equals(new Cell().hash())) {
        return undefined;
    }

    let s = cell.beginParse();
    try {
        const op = s.loadUint(32);
        switch (op) {
            case 0: {
                const str = s.loadStringTail();
                s.endParse();

                if (str.length > 120) {
                    throw new Error('Comment must be at most 120 ASCII characters long');
                }

                for (const c of str) {
                    if (c.charCodeAt(0) < 0x20 || c.charCodeAt(0) >= 0x7f) {
                        throw new Error('Comment must only contain printable ASCII characters');
                    }
                }

                return {
                    type: 'comment',
                    text: str,
                };
            }
            case 0x0f8a7ea5: {
                const queryId = normalizeQueryId(s.loadUintBig(64));
                const amount = s.loadCoins();
                const destination = s.loadAddress();
                const responseDestination = s.loadAddress();
                const customPayload = s.loadMaybeRef();
                const forwardAmount = s.loadCoins();

                let forwardPayload: Cell | null = null;
                if (s.loadBit()) {
                    forwardPayload = s.loadRef();
                } else {
                    const p = s.asCell();
                    s = new Cell().beginParse(); // clear the slice
                    if (!p.hash().equals(new Cell().hash())) {
                        if (params.disallowModification) {
                            throw new Error('Jetton transfer message would be modified');
                        }
                        forwardPayload = p;
                    }
                }

                s.endParse();

                return {
                    type: 'jetton-transfer',
                    queryId,
                    amount,
                    destination,
                    responseDestination,
                    customPayload,
                    forwardAmount,
                    forwardPayload,
                    knownJetton: null,
                };
            }
            case 0x5fcc3d14: {
                const queryId = normalizeQueryId(s.loadUintBig(64));
                const newOwner = s.loadAddress();
                const responseDestination = s.loadAddress();
                const customPayload = s.loadMaybeRef();
                const forwardAmount = s.loadCoins();

                let forwardPayload: Cell | null = null;
                if (s.loadBit()) {
                    forwardPayload = s.loadRef();
                } else {
                    const p = s.asCell();
                    s = new Cell().beginParse(); // clear the slice
                    if (!p.hash().equals(new Cell().hash())) {
                        if (params.disallowModification) {
                            throw new Error('Jetton transfer message would be modified');
                        }
                        forwardPayload = p;
                    }
                }

                s.endParse();

                return {
                    type: 'nft-transfer',
                    queryId,
                    newOwner,
                    responseDestination,
                    customPayload,
                    forwardAmount,
                    forwardPayload,
                };
            }
            case 0x595f07bc: {
                const queryId = normalizeQueryId(s.loadUintBig(64));
                const amount = s.loadCoins();
                const responseDestination = s.loadAddress();
                let customPayload: Cell | Buffer | null = s.loadMaybeRef();
                s.endParse();

                if (params.encodeJettonBurnEthAddressAsHex && customPayload !== null && customPayload.bits.length === 160 && customPayload.refs.length === 0) {
                    const cs = customPayload.beginParse();
                    customPayload = cs.loadBuffer(20);
                    cs.endParse();
                }

                return {
                    type: 'jetton-burn',
                    queryId,
                    amount,
                    responseDestination,
                    customPayload,
                };
            }
            case 0x7258a69b: {
                const queryId = normalizeQueryId(s.loadUintBig(64));
                const address = s.loadAddress();
                s.endParse();

                return {
                    type: 'add-whitelist',
                    queryId,
                    address,
                };
            }
            case 0x1000: {
                const queryId = normalizeQueryId(s.loadUintBig(64));
                const amount = s.loadCoins();
                s.endParse();

                return {
                    type: 'single-nominator-withdraw',
                    queryId,
                    amount,
                };
            }
            case 0x1001: {
                const queryId = normalizeQueryId(s.loadUintBig(64));
                const address = s.loadAddress();
                s.endParse();

                return {
                    type: 'single-nominator-change-validator',
                    queryId,
                    address,
                };
            }
            case 0x47d54391: {
                const queryId = normalizeQueryId(s.loadUintBig(64));
                let appId: bigint | null = null;
                if (s.remainingBits > 0) {
                    appId = s.loadUintBig(64);
                }
                s.endParse();

                return {
                    type: 'tonstakers-deposit',
                    queryId,
                    appId,
                };
            }
            case 0x69fb306c: {
                const queryId = normalizeQueryId(s.loadUintBig(64));
                const votingAddress = s.loadAddress();
                const expirationDate = s.loadUint(48);
                const vote = s.loadBit();
                const needConfirmation = s.loadBit();
                s.endParse();

                return {
                    type: 'vote-for-proposal',
                    queryId,
                    votingAddress,
                    expirationDate,
                    vote,
                    needConfirmation,
                };
            }
            case 0x4eb1f0f9: {
                const queryId = normalizeQueryId(s.loadUintBig(64));
                const key = s.loadBuffer(32);

                if (key.equals(dnsWalletKey)) {
                    if (s.remainingRefs > 0) {
                        const vs = s.loadRef().beginParse();
                        if (s.remainingBits > 0 && !params.disallowModification) {
                            // tolerate the Maybe bit
                            if (!s.loadBit()) throw new Error('Incorrect change DNS record message');
                        }
                        s.endParse();

                        const type = vs.loadUint(16);
                        if (type !== 0x9fd3) {
                            throw new Error('Wrong DNS record type');
                        }

                        const address = vs.loadAddress();
                        const flags = vs.loadUint(8);
                        if (flags > 1) {
                            throw new Error('DNS wallet record must have flags 0 or 1');
                        }
                        let capabilities: { isWallet: boolean } | null = (flags & 1) > 0 ? { isWallet: false } : null;
                        if (capabilities !== null) {
                            while (vs.loadBit()) {
                                const cap = vs.loadUint(16);
                                if (cap === 0x2177) {
                                    if (capabilities.isWallet && params.disallowModification) {
                                        throw new Error('DNS change record message would be modified');
                                    }
                                    capabilities.isWallet = true;
                                } else {
                                    throw new Error('Unknown DNS wallet record capability');
                                }
                            }
                        }

                        return {
                            type: 'change-dns-record',
                            queryId,
                            record: {
                                type: 'wallet',
                                value: {
                                    address,
                                    capabilities,
                                },
                            },
                        };
                    } else {
                        if (s.remainingBits > 0 && !params.disallowModification) {
                            // tolerate the Maybe bit
                            if (s.loadBit()) throw new Error('Incorrect change DNS record message');
                        }
                        s.endParse();

                        return {
                            type: 'change-dns-record',
                            queryId,
                            record: {
                                type: 'wallet',
                                value: null,
                            },
                        };
                    }
                } else {
                    if (s.remainingRefs > 0) {
                        const value = s.loadRef();
                        if (s.remainingBits > 0 && !params.disallowModification) {
                            // tolerate the Maybe bit
                            if (!s.loadBit()) throw new Error('Incorrect change DNS record message');
                        }
                        s.endParse();

                        return {
                            type: 'change-dns-record',
                            queryId,
                            record: {
                                type: 'unknown',
                                key,
                                value,
                            },
                        };
                    } else {
                        if (s.remainingBits > 0 && !params.disallowModification) {
                            // tolerate the Maybe bit
                            if (s.loadBit()) throw new Error('Incorrect change DNS record message');
                        }
                        s.endParse();

                        return {
                            type: 'change-dns-record',
                            queryId,
                            record: {
                                type: 'unknown',
                                key,
                                value: null,
                            },
                        };
                    }
                }
            }
            case 0x8: {
                const queryId = normalizeQueryId(s.loadUintBig(64));
                const swapId = s.loadBuffer(32);
                s.endParse();

                return {
                    type: 'token-bridge-pay-swap',
                    queryId,
                    swapId,
                };
            }
            case 0x7bcd1fef: {
                const queryId = s.loadUintBig(64);
                if (queryId <= 0n) {
                    throw new Error('Incorrect query id: must be greater than 0');
                }
                const gasLimit = s.loadCoins();
                s.endParse();
                return {
                    type: 'tonwhales-pool-deposit',
                    queryId,
                    gasLimit,
                };
            }
            case 0xda803efd: {
                const queryId = s.loadUintBig(64);
                if (queryId <= 0n) {
                    throw new Error('Incorrect query id: must be greater than 0');
                }
                const gasLimit = s.loadCoins();
                const amount = s.loadCoins();
                s.endParse();
                return {
                    type: 'tonwhales-pool-withdraw',
                    queryId,
                    gasLimit,
                    amount,
                };
            }
            case 0xa7733acd: {
                const queryId = normalizeQueryId(s.loadUintBig(64));
                const sendMode = s.loadUint(8);
                const msgRefSlice = s.loadRef().beginParse();
                s.endParse();
                
                const msg = loadMessageRelaxed(msgRefSlice);
                if (msg.info.type !== 'internal') {
                    throw new Error('Message is not internal');
                }

                const body = msg.body.beginParse();
                const op = body.loadUint(32);
                if (op !== 0) {
                    throw new Error('Message body is not a comment');
                }
                const text = body.loadStringTail();
                if (text.length > 120) {
                    throw new Error('Comment must be at most 120 ASCII characters long');
                }
                body.endParse();

                return {
                    type: 'vesting-send-msg-comment',
                    queryId,
                    sendMode,
                    value: msg.info.value.coins,
                    destination: msg.info.dest,
                    text,
                };
            }
        }
        throw new Error('Unknown op: ' + op);
    } catch (e) {
        if (params.disallowUnsafe) {
            throw e;
        }
    }

    return {
        type: 'unsafe',
        message: cell,
    };
}

export type SignDataRequest =
    | { type: 'plaintext', text: string }
    | { type: 'app-data', address?: Address, domain?: string, data: Cell, ext?: Cell }

export type SignDataNewRequestCommon = {
    domain: string;
}

export type SignDataNewRequestPartial =
    | { type: 'plaintext', text: string }
    | { type: 'binary', data: Buffer }
    | { type: 'app-data', schemaCrc: number, data: Cell }

export type SignDataNewRequest = SignDataNewRequestCommon & SignDataNewRequestPartial

function chunks(buf: Buffer, n: number): Buffer[] {
    const nc = Math.ceil(buf.length / n);
    const cs: Buffer[] = [];
    for (let i = 0; i < nc; i++) {
        cs.push(buf.subarray(i * n, (i + 1) * n));
    }
    return cs;
}

function processAddressFlags(opts?: { testOnly?: boolean, bounceable?: boolean, chain?: number, subwalletId?: number, walletVersion?: 'v3r2' | 'v4' }): { testOnly: boolean, bounceable: boolean, chain: number, flags: number, specifiers?: { subwalletId: number, isV3R2: boolean } } {
    const bounceable = opts?.bounceable ?? true;
    const testOnly = opts?.testOnly ?? false;
    const chain = opts?.chain ?? 0;
    const subwalletId = opts?.subwalletId ?? 698983191;
    const walletVersion = opts?.walletVersion ?? 'v4';
    let specifiers: { subwalletId: number, isV3R2: boolean } | undefined = undefined;

    let flags = 0x00;
    if (testOnly) {
        flags |= 0x01;
    }
    if (chain === -1) {
        flags |= 0x02;
    }
    if (subwalletId !== 698983191 || walletVersion !== 'v4') {
        flags |= 0x04;
        specifiers = {
            subwalletId,
            isV3R2: walletVersion === 'v3r2',
        };
    }

    return { bounceable, testOnly, chain, flags, specifiers };
}

function convertPayload(input: TonPayloadFormat | undefined): { payload: Cell | null, hints: Buffer } {
    let payload: Cell | null = null;
    let hints: Buffer = Buffer.concat([writeUint8(0)]);

    if (input === undefined) {
        return {
            payload,
            hints,
        };
    }

    switch (input.type) {
        case 'unsafe': {
            payload = input.message;
            break;
        }
        case 'comment': {
            hints = Buffer.concat([
                writeUint8(1),
                writeUint32(0x00),
                writeUint16(Buffer.from(input.text).length),
                Buffer.from(input.text)
            ]);
            payload = beginCell()
                .storeUint(0, 32)
                .storeBuffer(Buffer.from(input.text))
                .endCell();
            break;
        }
        case 'jetton-transfer':
        case 'nft-transfer': {
            hints = Buffer.concat([
                writeUint8(1),
                writeUint32(input.type === 'jetton-transfer' ? 0x01 : 0x02)
            ]);

            let b = beginCell()
                .storeUint(input.type === 'jetton-transfer' ? 0x0f8a7ea5 : 0x5fcc3d14, 32);
            let d = Buffer.alloc(0);

            let flags = 0;
            if (input.queryId !== null) {
                flags |= 1;
            }
            if (input.type === 'jetton-transfer' && input.knownJetton !== null) {
                flags |= 2;
            }

            d = Buffer.concat([d, writeUint8(flags)]);

            if (input.queryId !== null) {
                d = Buffer.concat([d, writeUint64(input.queryId)]);
                b = b.storeUint(input.queryId, 64);
            } else {
                b = b.storeUint(0, 64);
            }

            if (input.type === 'jetton-transfer') {
                if (input.knownJetton !== null) {
                    d = Buffer.concat([d, writeUint16(input.knownJetton.jettonId), writeUint8(input.knownJetton.workchain)]);
                }

                d = Buffer.concat([d, writeVarUInt(input.amount)]);
                b = b.storeCoins(input.amount);

                d = Buffer.concat([d, writeAddress(input.destination)]);
                b = b.storeAddress(input.destination);
            } else {
                d = Buffer.concat([d, writeAddress(input.newOwner)]);
                b = b.storeAddress(input.newOwner);
            }

            d = Buffer.concat([d, writeAddress(input.responseDestination)]);
            b = b.storeAddress(input.responseDestination);

            if (input.customPayload !== null) {
                d = Buffer.concat([d, writeUint8(1), writeCellRef(input.customPayload)]);
                b = b.storeMaybeRef(input.customPayload);
            } else {
                d = Buffer.concat([d, writeUint8(0)]);
                b = b.storeMaybeRef(input.customPayload);
            }

            d = Buffer.concat([d, writeVarUInt(input.forwardAmount)]);
            b = b.storeCoins(input.forwardAmount);

            if (input.forwardPayload !== null) {
                d = Buffer.concat([d, writeUint8(1), writeCellRef(input.forwardPayload)]);
                b = b.storeMaybeRef(input.forwardPayload);
            } else {
                d = Buffer.concat([d, writeUint8(0)]);
                b = b.storeMaybeRef(input.forwardPayload);
            }

            payload = b.endCell();
            hints = Buffer.concat([
                hints,
                writeUint16(d.length),
                d
            ]);
            break;
        }
        case 'jetton-burn': {
            hints = Buffer.concat([
                writeUint8(1),
                writeUint32(0x03)
            ]);

            let b = beginCell()
                .storeUint(0x595f07bc, 32);
            let d = Buffer.alloc(0);

            if (input.queryId !== null) {
                d = Buffer.concat([d, writeUint8(1), writeUint64(input.queryId)]);
                b = b.storeUint(input.queryId, 64);
            } else {
                d = Buffer.concat([d, writeUint8(0)]);
                b = b.storeUint(0, 64);
            }

            d = Buffer.concat([d, writeVarUInt(input.amount)]);
            b = b.storeCoins(input.amount);

            d = Buffer.concat([d, writeAddress(input.responseDestination)]);
            b = b.storeAddress(input.responseDestination);

            if (input.customPayload === null) {
                d = Buffer.concat([d, writeUint8(0)]);
                b = b.storeMaybeRef(input.customPayload);
            } else if (input.customPayload instanceof Cell) {
                d = Buffer.concat([d, writeUint8(1), writeCellRef(input.customPayload)]);
                b = b.storeMaybeRef(input.customPayload);
            } else {
                d = Buffer.concat([d, writeUint8(2), writeCellInline(input.customPayload)]);
                b = b.storeMaybeRef(beginCell().storeBuffer(input.customPayload).endCell());
            }

            payload = b.endCell();
            hints = Buffer.concat([
                hints,
                writeUint16(d.length),
                d
            ]);
            break;
        }
        case 'add-whitelist':
        case 'single-nominator-change-validator': {
            hints = Buffer.concat([
                writeUint8(1),
                writeUint32(input.type === 'add-whitelist' ? 0x04 : 0x06)
            ]);

            let b = beginCell()
                .storeUint(input.type === 'add-whitelist' ? 0x7258a69b : 0x1001, 32);
            let d = Buffer.alloc(0);

            if (input.queryId !== null) {
                d = Buffer.concat([d, writeUint8(1), writeUint64(input.queryId)]);
                b = b.storeUint(input.queryId, 64);
            } else {
                d = Buffer.concat([d, writeUint8(0)]);
                b = b.storeUint(0, 64);
            }

            d = Buffer.concat([d, writeAddress(input.address)]);
            b = b.storeAddress(input.address);

            payload = b.endCell();
            hints = Buffer.concat([
                hints,
                writeUint16(d.length),
                d
            ]);
            break;
        }
        case 'single-nominator-withdraw': {
            hints = Buffer.concat([
                writeUint8(1),
                writeUint32(0x05)
            ]);

            let b = beginCell()
                .storeUint(0x1000, 32);
            let d = Buffer.alloc(0);

            if (input.queryId !== null) {
                d = Buffer.concat([d, writeUint8(1), writeUint64(input.queryId)]);
                b = b.storeUint(input.queryId, 64);
            } else {
                d = Buffer.concat([d, writeUint8(0)]);
                b = b.storeUint(0, 64);
            }

            d = Buffer.concat([d, writeVarUInt(input.amount)]);
            b = b.storeCoins(input.amount);

            payload = b.endCell();
            hints = Buffer.concat([
                hints,
                writeUint16(d.length),
                d
            ]);
            break;
        }
        case 'tonstakers-deposit': {
            hints = Buffer.concat([
                writeUint8(1),
                writeUint32(0x07)
            ]);

            let b = beginCell()
                .storeUint(0x47d54391, 32);
            let d = Buffer.alloc(0);

            if (input.queryId !== null) {
                d = Buffer.concat([d, writeUint8(1), writeUint64(input.queryId)]);
                b = b.storeUint(input.queryId, 64);
            } else {
                d = Buffer.concat([d, writeUint8(0)]);
                b = b.storeUint(0, 64);
            }

            if (input.appId !== null) {
                d = Buffer.concat([d, writeUint8(1), writeUint64(input.appId)]);
                b = b.storeUint(input.appId, 64);
            } else {
                d = Buffer.concat([d, writeUint8(0)]);
            }

            payload = b.endCell();
            hints = Buffer.concat([
                hints,
                writeUint16(d.length),
                d
            ]);
            break;
        }
        case 'vote-for-proposal': {
            hints = Buffer.concat([
                writeUint8(1),
                writeUint32(0x08)
            ]);

            let b = beginCell()
                .storeUint(0x69fb306c, 32);
            let d = Buffer.alloc(0);

            if (input.queryId !== null) {
                d = Buffer.concat([d, writeUint8(1), writeUint64(input.queryId)]);
                b = b.storeUint(input.queryId, 64);
            } else {
                d = Buffer.concat([d, writeUint8(0)]);
                b = b.storeUint(0, 64);
            }

            d = Buffer.concat([d, writeAddress(input.votingAddress)]);
            b = b.storeAddress(input.votingAddress);

            d = Buffer.concat([d, writeUint48(input.expirationDate)]);
            b = b.storeUint(input.expirationDate, 48);

            d = Buffer.concat([d, writeUint8(input.vote ? 1 : 0), writeUint8(input.needConfirmation ? 1 : 0)]);
            b = b.storeBit(input.vote).storeBit(input.needConfirmation);

            payload = b.endCell();
            hints = Buffer.concat([
                hints,
                writeUint16(d.length),
                d
            ]);
            break;
        }
        case 'change-dns-record': {
            hints = Buffer.concat([
                writeUint8(1),
                writeUint32(0x09)
            ]);

            let b = beginCell()
                .storeUint(0x4eb1f0f9, 32);
            let d = Buffer.alloc(0);

            if (input.queryId !== null) {
                d = Buffer.concat([d, writeUint8(1), writeUint64(input.queryId)]);
                b = b.storeUint(input.queryId, 64);
            } else {
                d = Buffer.concat([d, writeUint8(0)]);
                b = b.storeUint(0, 64);
            }

            if (input.record.type === 'unknown' && input.record.key.length !== 32) {
                throw new Error('DNS record key length must be 32 bytes long');
            }
            b = b.storeBuffer(input.record.type === 'wallet' ? sha256_sync('wallet') : input.record.key);

            d = Buffer.concat([d, writeUint8(input.record.value === null ? 0 : 1), writeUint8(input.record.type === 'wallet' ? 0 : 1)]);

            if (input.record.type === 'wallet') {
                if (input.record.value !== null) {
                    d = Buffer.concat([d, writeAddress(input.record.value.address), writeUint8(input.record.value.capabilities === null ? 0 : 1)]);
                    let rb = beginCell().storeUint(0x9fd3, 16).storeAddress(input.record.value.address).storeUint(input.record.value.capabilities === null ? 0 : 1, 8);
                    if (input.record.value.capabilities !== null) {
                        d = Buffer.concat([d, writeUint8(input.record.value.capabilities.isWallet ? 1 : 0)]);
                        if (input.record.value.capabilities.isWallet) {
                            rb = rb.storeBit(true).storeUint(0x2177, 16);
                        }
                        rb = rb.storeBit(false);
                    }
                    b = b.storeRef(rb);
                }
            } else {
                d = Buffer.concat([d, input.record.key]);
                if (input.record.value !== null) {
                    d = Buffer.concat([d, writeCellRef(input.record.value)]);
                    b = b.storeRef(input.record.value);
                }
            }

            payload = b.endCell();
            hints = Buffer.concat([
                hints,
                writeUint16(d.length),
                d
            ]);
            break;
        }
        case 'token-bridge-pay-swap': {
            hints = Buffer.concat([
                writeUint8(1),
                writeUint32(0x0A)
            ]);

            let b = beginCell()
                .storeUint(8, 32);
            let d = Buffer.alloc(0);

            if (input.queryId !== null) {
                d = Buffer.concat([d, writeUint8(1), writeUint64(input.queryId)]);
                b = b.storeUint(input.queryId, 64);
            } else {
                d = Buffer.concat([d, writeUint8(0)]);
                b = b.storeUint(0, 64);
            }

            if (input.swapId.length !== 32) {
                throw new Error('Token bridge swap ID must be 32 bytes long');
            }

            d = Buffer.concat([d, input.swapId]);
            b = b.storeBuffer(input.swapId);

            payload = b.endCell();
            hints = Buffer.concat([
                hints,
                writeUint16(d.length),
                d
            ]);
            break;
        }
        case 'tonwhales-pool-deposit': {
            hints = Buffer.concat([
                writeUint8(1),
                writeUint32(0x0B)
            ]);

            const cell = beginCell()
                .storeUint(0x7bcd1fef, 32)
                .storeUint(input.queryId, 64)
                .storeCoins(input.gasLimit)
                .endCell();
            const buffer = Buffer.concat([
                writeUint64(input.queryId),
                writeVarUInt(input.gasLimit)    
            ]);

            payload = cell;
            hints = Buffer.concat([
                hints,
                writeUint16(buffer.length),
                buffer
            ]);

            break;
        }
        case 'tonwhales-pool-withdraw': {
            hints = Buffer.concat([
                writeUint8(1),
                writeUint32(0x0C)
            ]);
            
            const cell = beginCell()
                .storeUint(0xda803efd, 32)
                .storeUint(input.queryId, 64)
                .storeCoins(input.gasLimit)
                .storeCoins(input.amount)
                .endCell();
            const buffer = Buffer.concat([
                writeUint64(input.queryId),
                writeVarUInt(input.gasLimit),
                writeVarUInt(input.amount)
            ]); 

            payload = cell;
            hints = Buffer.concat([
                hints,
                writeUint16(buffer.length),
                buffer
            ]);
            break;
        }
        case 'vesting-send-msg-comment': {
            hints = Buffer.concat([
                writeUint8(1),
                writeUint32(0x0D)
            ]);
            
            let builder = beginCell()
                .storeUint(0xa7733acd, 32)
            let buffer = Buffer.alloc(0);

            if (input.queryId !== null) {
                builder = builder.storeUint(input.queryId, 64)
                buffer = Buffer.concat([buffer, writeUint8(1), writeUint64(input.queryId)]);
            }else{
                builder = builder.storeUint(0, 64)
                buffer = Buffer.concat([buffer, writeUint8(0)]);
            }

            builder = builder.storeUint(input.sendMode, 8);
            buffer = Buffer.concat([buffer, writeUint8(input.sendMode)]);

            const msg = internal({
                to: input.destination,
                value: input.value,
                body: beginCell().storeUint(0, 32).storeStringTail(input.text).endCell(),
            })

            const msgRefBuilder = beginCell();
            storeMessageRelaxed(msg)(msgRefBuilder);

            builder = builder.storeRef(msgRefBuilder.endCell());

            buffer = Buffer.concat([buffer, writeAddress(input.destination)]);
            buffer = Buffer.concat([buffer, writeVarUInt(input.value)]);
            if (input.text.length > 120) {
                throw new Error('Comment must be at most 120 ASCII characters long');
            }
            buffer = Buffer.concat([buffer, writeUint8(Buffer.from(input.text).length), Buffer.from(input.text)]);

            payload = builder.endCell();
            hints = Buffer.concat([
                hints,
                writeUint16(buffer.length),
                buffer
            ]);
            break;
        }
        default: {
            throw new Error('Unknown payload type: ' + (input as any).type);
        }
    }

    return {
        payload,
        hints,
    };
}

export class TonTransport {
    readonly transport: Transport;
    #lock = new AsyncLock();

    constructor(transport: Transport) {
        this.transport = transport;
    }

    //
    // Apps
    //

    async #getCurrentApp(): Promise<{ name: string, version: string }> {
        return this.#lock.inLock(async () => {
            let r = await this.transport.send(
                LEDGER_SYSTEM,
                0x01,
                0x00,
                0x00,
                undefined,
                [0x9000]
            );
            let data = r.slice(0, r.length - 2);
            if (data[0] !== 0x01) {
                throw Error('Invalid response');
            }
            let nameLength = data[1];
            let name = data.slice(2, 2 + nameLength).toString();
            let versionLength = data[2 + nameLength];
            let version = data.slice(3 + nameLength, 3 + nameLength + versionLength).toString();
            return { name, version };
        });
    }

    async isAppOpen() {
        return (await this.#getCurrentApp()).name === 'TON';
    }

    async getVersion(): Promise<string> {
        let loaded = await this.#doRequest(INS_VERSION, 0x00, 0x00, Buffer.alloc(0));
        const [major, minor, patch] = loaded;
        return `${major}.${minor}.${patch}`;
    }

    //
    // Operations
    //

    async getAddress(path: number[], opts?: { testOnly?: boolean, bounceable?: boolean, chain?: number, subwalletId?: number, walletVersion?: 'v3r2' | 'v4' }) {

        // Check path
        validatePath(path);

        // Resolve flags
        const { bounceable, testOnly, chain, specifiers } = processAddressFlags(opts);

        // Get public key
        let response = await this.#doRequest(INS_ADDRESS, 0x00, 0x00, pathElementsToBuffer(path.map((v) => v + 0x80000000)));
        if (response.length !== 32) {
            throw Error('Invalid response');
        }

        // Contract
        const contract = getInit(response, specifiers?.subwalletId ?? 698983191, specifiers?.isV3R2 ?? false);
        const address = contractAddress(chain, contract);

        return { address: address.toString({ bounceable, testOnly }), publicKey: response };
    }

    async validateAddress(path: number[], opts?: { testOnly?: boolean, bounceable?: boolean, chain?: number, subwalletId?: number, walletVersion?: 'v3r2' | 'v4' }) {

        // Check path
        validatePath(path);

        // Resolve flags
        const { bounceable, testOnly, chain, flags, specifiers } = processAddressFlags(opts);

        let r = pathElementsToBuffer(path.map((v) => v + 0x80000000));
        if (specifiers !== undefined) {
            r = Buffer.concat([r, writeUint8(specifiers.isV3R2 ? 1 : 0), writeUint32(specifiers.subwalletId)]);
        }

        // Get public key
        let response = await this.#doRequest(INS_ADDRESS, 0x01, flags, r);
        if (response.length !== 32) {
            throw Error('Invalid response');
        }

        // Contract
        const contract = getInit(response, specifiers?.subwalletId ?? 698983191, specifiers?.isV3R2 ?? false);
        const address = contractAddress(chain, contract);

        return { address: address.toString({ bounceable, testOnly }), publicKey: response };
    }

    async getAddressProof(path: number[], params: { domain: string, timestamp: number, payload: Buffer }, opts?: { testOnly?: boolean, bounceable?: boolean, chain?: number, subwalletId?: number, walletVersion?: 'v3r2' | 'v4' }) {

        // Check path
        validatePath(path);

        let publicKey = (await this.getAddress(path)).publicKey;

        // Resolve flags
        const { flags, specifiers } = processAddressFlags(opts);

        let specifiersBuf = Buffer.alloc(0);
        if (specifiers !== undefined) {
            specifiersBuf = Buffer.concat([writeUint8(specifiers.isV3R2 ? 1 : 0), writeUint32(specifiers.subwalletId)]);
        }

        const domainBuf = Buffer.from(params.domain, 'utf-8');
        const reqBuf = Buffer.concat([
            pathElementsToBuffer(path.map((v) => v + 0x80000000)),
            specifiersBuf,
            writeUint8(domainBuf.length),
            domainBuf,
            writeUint64(BigInt(params.timestamp)),
            params.payload,
        ]);

        // Get public key
        let res = await this.#doRequest(INS_PROOF, 0x01, flags, reqBuf);
        let signature = res.slice(1, 1 + 64);
        let hash = res.slice(2 + 64, 2 + 64 + 32);
        if (!signVerify(hash, signature, publicKey)) {
            throw Error('Received signature is invalid');
        }

        return { signature, hash };
    }

    async signData(path: number[], req: SignDataRequest, opts?: { timestamp?: number }) {
        validatePath(path);

        const publicKey = (await this.getAddress(path)).publicKey;

        const timestamp = opts?.timestamp ?? Math.floor(Date.now() / 1000)

        let schema: number
        let data: Buffer
        let cell: Cell
        switch (req.type) {
            case 'plaintext': {
                schema = 0x754bf91b;
                data = Buffer.from(req.text, 'ascii');
                cell = beginCell().storeStringTail(req.text).endCell();
                break;
            }
            case 'app-data': {
                if (req.address === undefined && req.domain === undefined) {
                    throw new Error('At least one of `address` and `domain` must be set when using \'app-data\' request');
                }
                schema = 0x54b58535;
                let b = beginCell();
                let dp: Buffer[] = [];

                if (req.address !== undefined) {
                    b.storeBit(1);
                    b.storeAddress(req.address);
                    dp.push(writeUint8(1), writeAddress(req.address));
                } else {
                    b.storeBit(0);
                    dp.push(writeUint8(0));
                }

                if (req.domain !== undefined) {
                    b.storeBit(1);
                    let inner = beginCell();
                    req.domain.split('.').reverse().forEach(p => {
                        inner.storeBuffer(Buffer.from(p, 'ascii'));
                        inner.storeUint(0, 8);
                    });
                    b.storeRef(inner);
                    const db = Buffer.from(req.domain, 'ascii');
                    dp.push(writeUint8(1), writeUint8(db.length), db);
                } else {
                    b.storeBit(0);
                    dp.push(writeUint8(0));
                }

                b.storeRef(req.data);
                dp.push(writeCellRef(req.data));

                if (req.ext !== undefined) {
                    b.storeBit(1);
                    b.storeRef(req.ext);
                    dp.push(writeUint8(1), writeCellRef(req.ext));
                } else {
                    b.storeBit(0);
                    dp.push(writeUint8(0));
                }

                data = Buffer.concat(dp);
                cell = b.endCell();
                break;
            }
            default: {
                throw new Error(`Sign data request type '${(req as any).type}' not supported`)
            }
        }

        const commonPart = Buffer.concat([
            writeUint32(schema),
            writeUint64(BigInt(timestamp)),
        ]);

        const pkg = Buffer.concat([
            commonPart,
            data,
        ])

        await this.#doRequest(INS_SIGN_DATA, 0x00, 0x03, pathElementsToBuffer(path.map((v) => v + 0x80000000)));
        const pkgCs = chunks(pkg, 255);
        for (let i = 0; i < pkgCs.length - 1; i++) {
            await this.#doRequest(INS_SIGN_DATA, 0x00, 0x02, pkgCs[i]);
        }
        const res = await this.#doRequest(INS_SIGN_DATA, 0x00, 0x00, pkgCs[pkgCs.length-1]);

        let signature = res.subarray(1, 1 + 64);
        let hash = res.subarray(2 + 64, 2 + 64 + 32);
        if (!hash.equals(cell.hash())) {
            throw Error('Hash mismatch. Expected: ' + cell.hash().toString('hex') + ', got: ' + hash.toString('hex'));
        }
        if (!signVerify(Buffer.concat([commonPart, hash]), signature, publicKey)) {
            throw Error('Received signature is invalid');
        }

        return {
            signature,
            cell,
            timestamp,
        }
    }

    async signDataNew(path: number[], req: SignDataNewRequest, opts?: { timestamp?: number, testOnly?: boolean, chain?: number, subwalletId?: number, walletVersion?: 'v3r2' | 'v4' }) {
        validatePath(path);

        const { publicKey, address: addressString } = (await this.getAddress(path, opts));
        const expectedAddress = Address.parse(addressString);

        const { flags, specifiers, chain } = processAddressFlags(opts);

        let specifiersBuf = Buffer.alloc(0);
        if (specifiers !== undefined) {
            specifiersBuf = Buffer.concat([writeUint8(specifiers.isV3R2 ? 1 : 0), writeUint32(specifiers.subwalletId)]);
        }

        const timestamp = opts?.timestamp ?? Math.floor(Date.now() / 1000)

        const domainBuf = Buffer.from(req.domain, 'ascii');

        let typeId: number
        let payload: Buffer
        let signedData: Cell | Buffer
        switch (req.type) {
            case 'plaintext': {
                typeId = 0;
                payload = Buffer.from(req.text, 'ascii');
                signedData = Buffer.concat([
                    Buffer.from([0xff, 0xff]),
                    Buffer.from('ton-connect/sign-data/'),
                    writeInt32BE(chain),
                    expectedAddress.hash,
                    writeUint32(domainBuf.length),
                    domainBuf,
                    writeUint64(BigInt(timestamp)),
                    Buffer.from('txt', 'ascii'),
                    writeUint32(payload.length),
                    payload,
                ]);
                break;
            }
            case 'binary': {
                typeId = 1;
                payload = req.data;
                signedData = Buffer.concat([
                    Buffer.from([0xff, 0xff]),
                    Buffer.from('ton-connect/sign-data/'),
                    writeInt32BE(chain),
                    expectedAddress.hash,
                    writeUint32(domainBuf.length),
                    domainBuf,
                    writeUint64(BigInt(timestamp)),
                    Buffer.from('bin', 'ascii'),
                    writeUint32(payload.length),
                    payload,
                ]);
                break;
            }
            case 'app-data': {
                typeId = 2;
                payload = Buffer.concat([
                    writeUint32(req.schemaCrc),
                    writeCellRef(req.data),
                ]);

                let inner = beginCell();
                req.domain.split('.').reverse().forEach(p => {
                    inner.storeBuffer(Buffer.from(p, 'ascii'));
                    inner.storeUint(0, 8);
                });

                signedData = beginCell()
                    .storeUint(0x75569022, 32) // prefix
                    .storeUint(req.schemaCrc, 32) // schema hash
                    .storeUint(timestamp, 64) // timestamp
                    .storeAddress(expectedAddress) // user wallet address
                    .storeRef(inner) // domain
                    .storeRef(req.data) // payload cell
                    .endCell();

                break;
            }
            default: {
                throw new Error(`Sign data request type '${(req as any).type}' not supported`)
            }
        }

        const pkg = Buffer.concat([
            writeUint8(typeId),
            writeUint8(flags),
            specifiersBuf,
            writeUint8(domainBuf.length),
            domainBuf,
            writeUint64(BigInt(timestamp)),
            payload,
        ]);

        await this.#doRequest(INS_SIGN_DATA, 0x01, 0x03, pathElementsToBuffer(path.map((v) => v + 0x80000000)));
        const pkgCs = chunks(pkg, 255);
        for (let i = 0; i < pkgCs.length - 1; i++) {
            await this.#doRequest(INS_SIGN_DATA, 0x01, 0x02, pkgCs[i]);
        }
        const res = await this.#doRequest(INS_SIGN_DATA, 0x01, 0x00, pkgCs[pkgCs.length-1]);

        let signature = res.subarray(1, 1 + 64);
        let hash = res.subarray(2 + 64, 2 + 64 + 32);

        const signedDataHash = signedData instanceof Cell ? signedData.hash() : sha256_sync(signedData);

        if (!hash.equals(signedDataHash)) {
            throw Error('Hash mismatch. Expected: ' + signedDataHash.toString('hex') + ', got: ' + hash.toString('hex'));
        }
        if (!signVerify(signedDataHash, signature, publicKey)) {
            throw Error('Received signature is invalid');
        }

        return {
            signature,
            address: expectedAddress,
            signedData,
            signedDataHash,
            timestamp,
        }
    }

    signTransaction = async (
        path: number[],
        transaction: {
            to: Address,
            sendMode: SendMode,
            seqno: number,
            timeout: number,
            bounce: boolean,
            amount: bigint,
            stateInit?: StateInit,
            payload?: TonPayloadFormat,
            walletSpecifiers?: {
                subwalletId?: number,
                includeWalletOp: boolean,
            },
            extraCurrency?: {
                index: number,
                amount: bigint,
            },
        }
    ) => {

        // Check path
        validatePath(path);

        if (transaction.extraCurrency !== undefined && transaction.extraCurrency.index >= KNOWN_EXTRA_CURRENCIES.length) {
            throw Error('Invalid extra currency index');
        }

        //
        // Fetch key
        //

        let publicKey = (await this.getAddress(path)).publicKey;

        //
        // Create package
        //

        const includeWalletOp = transaction.walletSpecifiers?.includeWalletOp ?? true;
        const subwalletId = transaction.walletSpecifiers?.subwalletId ?? DEFAULT_SUBWALLET_ID;

        const useTag1 = transaction.walletSpecifiers !== undefined || transaction.extraCurrency !== undefined;

        let pkg = Buffer.concat([
            writeUint8(useTag1 ? 1 : 0), // tag
        ]);

        if (useTag1) {
            let flags = 0;
            if (includeWalletOp) {
                flags |= 1;
            }
            if (transaction.extraCurrency !== undefined) {
                flags |= 2;
            }

            pkg = Buffer.concat([
                pkg,
                writeUint32(subwalletId),
                writeUint8(flags),
            ]);
        }

        let ecBuf = Buffer.alloc(0);
        if (transaction.extraCurrency !== undefined) {
            ecBuf = Buffer.concat([
                writeUint8(transaction.extraCurrency.index),
                writeVarUInt(transaction.extraCurrency.amount),
            ]);
        }

        pkg = Buffer.concat([
            pkg,
            writeUint32(transaction.seqno),
            writeUint32(transaction.timeout),
            writeVarUInt(transaction.amount),
            ecBuf,
            writeAddress(transaction.to),
            writeUint8(transaction.bounce ? 1 : 0),
            writeUint8(transaction.sendMode),
        ]);

        //
        // State init
        //

        let stateInit: Cell | null = null;
        if (transaction.stateInit) {
            stateInit = beginCell()
                .store(storeStateInit(transaction.stateInit))
                .endCell();
            pkg = Buffer.concat([
                pkg,
                writeUint8(1),
                writeUint16(stateInit.depth()),
                stateInit.hash()
            ])
        } else {
            pkg = Buffer.concat([
                pkg,
                writeUint8(0)
            ]);
        }

        //
        // Payload
        //

        const { payload, hints } = convertPayload(transaction.payload);

        if (payload) {
            pkg = Buffer.concat([
                pkg,
                writeUint8(1),
                writeUint16(payload.depth()),
                payload.hash(),
                hints
            ])
        } else {
            pkg = Buffer.concat([
                pkg,
                writeUint8(0),
                writeUint8(0)
            ]);
        }

        //
        // Send package
        //

        await this.#doRequest(INS_SIGN_TX, 0x00, 0x03, pathElementsToBuffer(path.map((v) => v + 0x80000000)));
        const pkgCs = chunks(pkg, 255);
        for (let i = 0; i < pkgCs.length - 1; i++) {
            await this.#doRequest(INS_SIGN_TX, 0x00, 0x02, pkgCs[i]);
        }
        let res = await this.#doRequest(INS_SIGN_TX, 0x00, 0x00, pkgCs[pkgCs.length-1]);

        //
        // Parse response
        //

        let orderBuilder = beginCell()
            .storeBit(0)
            .storeBit(true)
            .storeBit(transaction.bounce)
            .storeBit(false)
            .storeAddress(null)
            .storeAddress(transaction.to)
            .storeCoins(transaction.amount)

        if (transaction.extraCurrency !== undefined) {
            orderBuilder = orderBuilder
                .storeBit(true)
                .storeRef(beginCell()
                    .storeUint(0b10, 2)
                    .storeUint(32, 6)
                    .storeUint(KNOWN_EXTRA_CURRENCIES[transaction.extraCurrency.index].id, 32)
                    .storeVarUint(transaction.extraCurrency.amount, 5))
        } else {
            orderBuilder = orderBuilder.storeBit(false)
        }

        orderBuilder = orderBuilder
            .storeCoins(0)
            .storeCoins(0)
            .storeUint(0, 64)
            .storeUint(0, 32)

        // State Init
        if (stateInit) {
            orderBuilder = orderBuilder
                .storeBit(true)
                .storeBit(true) // Always in reference
                .storeRef(stateInit)
        } else {
            orderBuilder = orderBuilder
                .storeBit(false);
        }

        // Payload
        if (payload) {
            orderBuilder = orderBuilder
                .storeBit(true) // Always in reference
                .storeRef(payload)
        } else {
            orderBuilder = orderBuilder
                .storeBit(false)
        }

        // Transfer message
        let transferB = beginCell()
            .storeUint(subwalletId, 32)
            .storeUint(transaction.timeout, 32)
            .storeUint(transaction.seqno, 32);

        if (includeWalletOp) {
            transferB = transferB.storeUint(0, 8)
        }

        let transfer = transferB.storeUint(transaction.sendMode, 8)
            .storeRef(orderBuilder.endCell())
            .endCell();

        // Parse result
        let signature = res.slice(1, 1 + 64);
        let hash = res.slice(2 + 64, 2 + 64 + 32);
        if (!hash.equals(transfer.hash())) {
            throw Error('Hash mismatch. Expected: ' + transfer.hash().toString('hex') + ', got: ' + hash.toString('hex'));
        }
        if (!signVerify(hash, signature, publicKey)) {
            throw Error('Received signature is invalid');
        }

        // Build a message
        return beginCell()
            .storeBuffer(signature)
            .storeSlice(transfer.beginParse())
            .endCell();
    }

    async getSettings(): Promise<{
        blindSigningEnabled: boolean
        expertMode: boolean
    }> {
        let loaded = await this.#doRequest(INS_SETTINGS, 0x00, 0x00, Buffer.alloc(0));
        return {
            blindSigningEnabled: (loaded[0] & 0x01) > 0,
            expertMode: (loaded[0] & 0x02) > 0,
        };
    }

    async launchApp() {
        await this.#doRequest(0xd8, 0x00, 0x00, Buffer.from('TON', 'ascii'));
    }

    #doRequest = async (ins: number, p1: number, p2: number, data: Buffer) => {
        return this.#lock.inLock(async () => {
            let r = await this.transport.send(
                LEDGER_CLA,
                ins,
                p1,
                p2,
                data
            );
            return r.slice(0, r.length - 2);
        });
    }
}

//
// Utils
//

function validatePath(path: number[]) {
    if (path.length < 6) {
        throw Error('Path is too short');
    }
    if (path[0] !== 44) {
        throw Error('First element of a path must be 44');
    }
    if (path[1] !== 607) {
        throw Error('Second element of a path must be 607');
    }
    for (let p of path) {
        if (p >= 0x80000000) {
            throw Error('All path elements must be under 0x80000000');
        }
    }
}

function pathElementsToBuffer(paths: number[]): Buffer {
    const buffer = Buffer.alloc(1 + paths.length * 4);
    buffer[0] = paths.length;
    paths.forEach((element, index) => {
        buffer.writeUInt32BE(element, 1 + 4 * index);
    });
    return buffer;
}

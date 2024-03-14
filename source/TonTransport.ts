import Transport from "@ledgerhq/hw-transport";
import { Address, beginCell, Cell, contractAddress, SendMode, StateInit, storeStateInit } from "@ton/core";
import { sha256_sync, signVerify } from '@ton/crypto';
import { AsyncLock } from 'teslabot';
import { writeAddress, writeCellInline, writeCellRef, writeUint16, writeUint32, writeUint48, writeUint64, writeUint8, writeVarUInt } from "./utils/ledgerWriter";
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

export type TonPayloadFormat =
    | { type: 'unsafe', message: Cell }
    | { type: 'comment', text: string }
    | { type: 'jetton-transfer', queryId: bigint | null, amount: bigint, destination: Address, responseDestination: Address, customPayload: Cell | null, forwardAmount: bigint, forwardPayload: Cell | null }
    | { type: 'nft-transfer', queryId: bigint | null, newOwner: Address, responseDestination: Address, customPayload: Cell | null, forwardAmount: bigint, forwardPayload: Cell | null }
    | { type: 'jetton-burn', queryId: bigint | null, amount: bigint, responseDestination: Address, customPayload: Cell | Buffer | null }
    | { type: 'add-whitelist', queryId: bigint | null, address: Address }
    | { type: 'single-nominator-withdraw', queryId: bigint | null, amount: bigint }
    | { type: 'single-nominator-change-validator', queryId: bigint | null, address: Address }
    | { type: 'tonstakers-deposit', queryId: bigint | null, appId: bigint | null }
    | { type: 'vote-for-proposal', queryId: bigint | null, votingAddress: Address, expirationDate: number, vote: boolean, needConfirmation: boolean }
    | { type: 'change-dns-record', queryId: bigint | null, record: { type: 'wallet', value: { address: Address, capabilities: { isWallet: boolean } | null } | null } | { type: 'unknown', key: Buffer, value: Cell | null } }
    | { type: 'token-bridge-pay-swap', queryId: bigint | null, swapId: Buffer }

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

function chunks(buf: Buffer, n: number): Buffer[] {
    const nc = Math.ceil(buf.length / n);
    const cs: Buffer[] = [];
    for (let i = 0; i < nc; i++) {
        cs.push(buf.subarray(i * n, (i + 1) * n));
    }
    return cs;
}

function processAddressFlags(opts?: { testOnly?: boolean, bounceable?: boolean, chain?: number }): { testOnly: boolean, bounceable: boolean, chain: number, flags: number } {
    const bounceable = opts?.bounceable ?? true;
    const testOnly = opts?.testOnly ?? false;
    const chain = opts?.chain ?? 0;

    let flags = 0x00;
    if (testOnly) {
        flags |= 0x01;
    }
    if (chain === -1) {
        flags |= 0x02;
    }

    return { bounceable, testOnly, chain, flags };
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

            if (input.queryId !== null) {
                d = Buffer.concat([d, writeUint8(1), writeUint64(input.queryId)]);
                b = b.storeUint(input.queryId, 64);
            } else {
                d = Buffer.concat([d, writeUint8(0)]);
                b = b.storeUint(0, 64);
            }

            if (input.type === 'jetton-transfer') {
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

    async getAddress(path: number[], opts?: { testOnly?: boolean, bounceable?: boolean, chain?: number }) {

        // Check path
        validatePath(path);

        // Resolve flags
        const { bounceable, testOnly, chain } = processAddressFlags(opts);

        // Get public key
        let response = await this.#doRequest(INS_ADDRESS, 0x00, 0x00, pathElementsToBuffer(path.map((v) => v + 0x80000000)));
        if (response.length !== 32) {
            throw Error('Invalid response');
        }

        // Contract
        const contract = getInit(chain, response);
        const address = contractAddress(chain, contract);

        return { address: address.toString({ bounceable, testOnly }), publicKey: response };
    }

    async validateAddress(path: number[], opts?: { testOnly?: boolean, bounceable?: boolean, chain?: number }) {

        // Check path
        validatePath(path);

        // Resolve flags
        const { bounceable, testOnly, chain, flags } = processAddressFlags(opts);

        // Get public key
        let response = await this.#doRequest(INS_ADDRESS, 0x01, flags, pathElementsToBuffer(path.map((v) => v + 0x80000000)));
        if (response.length !== 32) {
            throw Error('Invalid response');
        }

        // Contract
        const contract = getInit(chain, response);
        const address = contractAddress(chain, contract);

        return { address: address.toString({ bounceable, testOnly }), publicKey: response };
    }

    async getAddressProof(path: number[], params: { domain: string, timestamp: number, payload: Buffer }, opts?: { testOnly?: boolean, bounceable?: boolean, chain?: number }) {

        // Check path
        validatePath(path);

        let publicKey = (await this.getAddress(path)).publicKey;

        // Resolve flags
        const { flags } = processAddressFlags(opts);

        const domainBuf = Buffer.from(params.domain, 'utf-8');
        const reqBuf = Buffer.concat([
            pathElementsToBuffer(path.map((v) => v + 0x80000000)),
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
        }
    ) => {

        // Check path
        validatePath(path);

        //
        // Fetch key
        //

        let publicKey = (await this.getAddress(path)).publicKey;

        //
        // Create package
        //

        let pkg = Buffer.concat([
            writeUint8(transaction.walletSpecifiers === undefined ? 0 : 1), // tag
        ]);

        if (transaction.walletSpecifiers !== undefined) {
            pkg = Buffer.concat([
                pkg,
                writeUint32(transaction.walletSpecifiers.subwalletId ?? DEFAULT_SUBWALLET_ID),
                writeUint8(transaction.walletSpecifiers.includeWalletOp ? 1 : 0),
            ]);
        }

        pkg = Buffer.concat([
            pkg,
            writeUint32(transaction.seqno),
            writeUint32(transaction.timeout),
            writeVarUInt(transaction.amount),
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
            .storeBit(false)
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
            .storeUint(transaction.walletSpecifiers?.subwalletId ?? DEFAULT_SUBWALLET_ID, 32)
            .storeUint(transaction.timeout, 32)
            .storeUint(transaction.seqno, 32);

        if (transaction.walletSpecifiers?.includeWalletOp ?? true) {
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
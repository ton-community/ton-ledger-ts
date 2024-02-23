import { Address, Cell, beginCell } from '@ton/core';

export function writeUint32(value: number) {
    let b = Buffer.alloc(4);
    b.writeUint32BE(value, 0);
    return b;
}

export function writeUint16(value: number) {
    let b = Buffer.alloc(2);
    b.writeUint16BE(value, 0);
    return b;
}

export function writeUint48(value: number) {
    let b = Buffer.alloc(6);
    b.writeUint16BE(value >> 32, 0);
    b.writeUint32BE(value & ((1 << 32) - 1), 2);
    return b;
}

export function writeUint64(value: bigint) {
    return beginCell().storeUint(value, 64).endCell().beginParse().loadBuffer(8);
}

export function writeVarUInt(value: bigint) {
    const sizeBytes = value === 0n ? 0 : Math.ceil((value.toString(2).length) / 8);
    return beginCell().storeUint(sizeBytes, 8).storeUint(value, sizeBytes * 8).endCell().beginParse().loadBuffer(1 + sizeBytes);
}

export function writeUint8(value: number) {
    let b = Buffer.alloc(1);
    b[0] = value;
    return b;
}

export function writeAddress(address: Address) {
    return Buffer.concat([
        writeUint8(address.workChain === -1 ? 0xff : address.workChain),
        address.hash
    ]);
}

export function writeCellRef(ref: Cell) {
    return Buffer.concat([
        writeUint16(ref.depth()),
        ref.hash()
    ])
}

export function writeCellInline(bytes: Buffer) {
    return Buffer.concat([
        writeUint8(bytes.length),
        bytes,
    ]);
}

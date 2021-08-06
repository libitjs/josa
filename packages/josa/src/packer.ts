import * as msgpack from 'msgpackr';
import {Buffer} from 'buffer';
import {Packet, Signature} from './types';

export interface Packer<T = Buffer> {
  pack(packet: Packet): T;

  unpack(data: T): Packet;
}

export class DefaultPacker implements Packer {
  pack(packet: Packet) {
    return msgpack.pack([packet.header, packet.payload, packet.signatures.map(s => [s.idt, s.alg, s.sig])]);
  }

  unpack(data: Buffer): Packet {
    const [header, payload, sigs] = msgpack.unpack(data);
    const signatures: Signature[] = sigs.map(([idt, alg, sig]: string[]) => ({idt, alg, sig}));
    return {header, payload, signatures};
  }
}

export const packer = new DefaultPacker();

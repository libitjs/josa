import {base64} from '@libit/crypto';
import {Packer, Packet} from '@libit/josa';
import * as msgpack from 'msgpackr';

export class JotPacker implements Packer<string> {
  pack(packet: Packet): string {
    const s1 = encode(packet.header);
    const s2 = encode(packet.payload);
    const s3 = encode(packet.signatures.map(({idt, alg, sig}) => [idt, alg, sig]));
    return [s1, s2, s3].join('.');
  }

  unpack(token: string): Packet {
    const [s1, s2, s3] = token.split('.');
    if (s1 == null || s2 == null || !s3 == null) {
      throw new Error('invalid token');
    }
    return {
      header: decode(s1),
      payload: decode(s2),
      signatures: decode(s3).map(([idt, alg, sig]: string[]) => ({idt, alg, sig})),
    };
  }
}

function encode(target: any) {
  return base64.encodeURL(msgpack.pack(target));
}

function decode(data: string) {
  return msgpack.unpack(base64.decodeURL(data));
}

export const packer = new JotPacker();

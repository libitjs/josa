import {ed25519} from '@libit/crypto/ed25519';
import {SHA512} from '@libit/crypto/sha512';
import {expect} from '@loopback/testlab';
import {KeyPair} from '../types';
import {Signer} from '../signer';
import {Box} from '../box';
import {packer} from '../packer';

const SAMPLE_PAYLOAD = {action: 'send'};

describe('packer', function () {
  let box: Box;
  let signer: Signer;
  let key: KeyPair;

  before(() => {
    box = new Box(ed25519, SHA512);
    signer = new Signer({box});
    key = box.createKeyPair();
  });

  it('pack()', function () {
    const packet = signer.sign(SAMPLE_PAYLOAD, key);
    const token = packer.pack(packet);
    expect(token).ok();
  });

  it('unpack()', function () {
    const packet = signer.sign(SAMPLE_PAYLOAD, key);
    const token = packer.pack(packet);
    const packetUnpacked = packer.unpack(token);
    expect(packet).eql(packetUnpacked);
  });
});

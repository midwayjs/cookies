import * as assert from 'assert';
import { Keygrip } from '../src/keygrip';

describe('test/keygrip.test.ts', () => {
  it('should throw without keys', () => {
    assert(shouldThrow(() => new Keygrip()) === 'keys must be provided and should be an array');
    assert(shouldThrow(() => new Keygrip([])) === 'keys must be provided and should be an array');
    assert(shouldThrow(() => new Keygrip('hello' as any)) === 'keys must be provided and should be an array');
  });

  it('should encrypt and decrypt success', () => {
    const keygrip = new Keygrip([ 'foo', 'bar' ]);
    const newKeygrip = new Keygrip([ 'another', 'foo' ]);

    const encrypted = keygrip.encrypt('hello');
    assert(keygrip.decrypt(encrypted).value.toString() === 'hello');
    assert(keygrip.decrypt(encrypted).index === 0);
    assert(newKeygrip.decrypt(encrypted).value.toString() === 'hello');
    assert(newKeygrip.decrypt(encrypted).index === 1);
  });

  it('should encrypt and decrypt with other language success', () => {
    const keygrip = new Keygrip([ 'foo', 'bar' ]);
    const newKeygrip = new Keygrip([ 'another', 'foo' ]);

    const encrypted = keygrip.encrypt('你好');
    assert(keygrip.decrypt(encrypted).value.toString() === '你好');
    assert(keygrip.decrypt(encrypted).index === 0);
    assert(newKeygrip.decrypt(encrypted).value.toString() === '你好');
    assert(newKeygrip.decrypt(encrypted).index === 1);
  });

  it('should decrypt error return false', () => {
    const keygrip = new Keygrip([ 'foo', 'bar' ]);
    const newKeygrip = new Keygrip([ 'another' ]);

    const encrypted = keygrip.encrypt('hello');
    assert(keygrip.decrypt(encrypted).value.toString() === 'hello');
    assert(keygrip.decrypt(encrypted).index === 0);
    assert(newKeygrip.decrypt(encrypted) === false);
  });

  it('should signed and verify success', () => {
    const keygrip = new Keygrip([ 'foo', 'bar' ]);
    const newKeygrip = new Keygrip([ 'another', 'foo' ]);

    const signed = keygrip.sign('hello');
    assert(keygrip.verify('hello', signed) === 0);
    assert(newKeygrip.verify('hello', signed) === 1);
  });

  it('should signed and verify failed return -1', () => {
    const keygrip = new Keygrip([ 'foo', 'bar' ]);
    const newKeygrip = new Keygrip([ 'another' ]);

    const signed = keygrip.sign('hello');
    assert(keygrip.verify('hello', signed) === 0);
    assert(newKeygrip.verify('hello', signed) === -1);
  });

  it('should test encrypt error', function () {
    const keygrip = new Keygrip([ 'foo', 'bar' ]);
    const encrypted = keygrip.encrypt('hello', {});
    expect(encrypted).toBeUndefined();
  });

  it('should test decrypt error', function () {
    const keygrip = new Keygrip([ 'foo', 'bar' ]);
    const value = keygrip.decrypt('hello');
    expect(value.value).toBeUndefined();
  });
});

function shouldThrow(fn) {
  try {
    fn();
  } catch (err) {
    return err.message;
  }
  throw new Error('not thrown');
}

// c.f. https://gist.github.com/kiasaki/9e69449640fc1ec29e0def97e1ddd6bf

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const PAD = '=';

export const base32 = {
  decode: function (s) {
    const len = s.length;
    const apad = ALPHABET + PAD;
    let v,
      x,
      r = 0,
      bits = 0,
      c,
      o = "";

    s = s.toUpperCase();

    for (let i = 0; i < len; i += 1) {
      v = apad.indexOf(s.charAt(i));
      if (v >= 0 && v < 32) {
        x = (x << 5) | v;
        bits += 5;
        if (bits >= 8) {
          c = (x >> (bits - 8)) & 0xff;
          o = o + String.fromCharCode(c);
          bits -= 8;
        }
      }
    }
    // remaining bits are < 8
    if (bits > 0) {
      c = ((x << (8 - bits)) & 0xff) >> (8 - bits);
      // Don't append a null terminator.
      // See the comment at the top about why this sucks.
      if (c !== 0) {
        o = o + String.fromCharCode(c);
      }
    }
    return Uint8Array.from(o, (char) => char.charCodeAt(0));
  },
};

#ifndef EC_CL
#define EC_CL

#define SECP256K1_B 7

#define SECP256K1_P0 0xfffffc2f
#define SECP256K1_P1 0xfffffffe
#define SECP256K1_P2 0xffffffff
#define SECP256K1_P3 0xffffffff
#define SECP256K1_P4 0xffffffff
#define SECP256K1_P5 0xffffffff
#define SECP256K1_P6 0xffffffff
#define SECP256K1_P7 0xffffffff

#define SECPK256K_VALUES                                                       \
  SECP256K1_P0, SECP256K1_P1, SECP256K1_P2, SECP256K1_P3, SECP256K1_P4,        \
      SECP256K1_P5, SECP256K1_P6, SECP256K1_P7

__constant uint secpk256PreComputed[96] = {
    0x16f81798, 0x59f2815b, 0x2dce28d9, 0x029bfcdb, 0xce870b07, 0x55a06295,
    0xf9dcbbac, 0x79be667e, 0xfb10d4b8, 0x9c47d08f, 0xa6855419, 0xfd17b448,
    0x0e1108a8, 0x5da4fbfc, 0x26a3c465, 0x483ada77, 0x04ef2777, 0x63b82f6f,
    0x597aabe6, 0x02e84bb7, 0xf1eef757, 0xa25b0403, 0xd95c3b9a, 0xb7c52588,
    0xbce036f9, 0x8601f113, 0x836f99b0, 0xb531c845, 0xf89d5229, 0x49344f85,
    0x9258c310, 0xf9308a01, 0x84b8e672, 0x6cb9fd75, 0x34c2231b, 0x6500a999,
    0x2a37f356, 0x0fe337e6, 0x632de814, 0x388f7b0f, 0x7b4715bd, 0x93460289,
    0xcb3ddce4, 0x9aff5666, 0xd5c80ca9, 0xf01cc819, 0x9cd217eb, 0xc77084f0,
    0xb240efe4, 0xcba8d569, 0xdc619ab7, 0xe88b84bd, 0x0a5c5128, 0x55b4a725,
    0x1a072093, 0x2f8bde4d, 0xa6ac62d6, 0xdca87d3a, 0xab0d6840, 0xf788271b,
    0xa6c9c426, 0xd4dba9dd, 0x36e5e3d6, 0xd8ac2226, 0x59539959, 0x235782c4,
    0x54f297bf, 0x0877d8e4, 0x59363bd9, 0x2b245622, 0xc91a1c29, 0x2753ddd9,
    0xcac4f9bc, 0xe92bdded, 0x0330e39c, 0x3d419b7e, 0xf2ea7a0e, 0xa398f365,
    0x6e5db4ea, 0x5cbdf064, 0x087264da, 0xa5082628, 0x13fde7b5, 0xa813d0b8,
    0x861a54db, 0xa3178d6d, 0xba255960, 0x6aebca40, 0xf78d9755, 0x5af7d9d6,
    0xec02184a, 0x57ec2f47, 0x79e5ab24, 0x5ce87292, 0x45daa69f, 0x951435bf};

#define SECP256K1_PRE_COMPUTED_XY_SIZE 96
#define SECP256K1_NAF_SIZE 33

#define is_zero(n)                                                             \
  (!n[8] && !n[7] && !n[6] && !n[5] && !n[4] && !n[3] && !n[2] && !n[1] &&     \
   !n[0])

#define shift_first(aElem, lastValue)                                          \
  (aElem)[0] = (aElem)[0] >> 1 | (aElem)[1] << 31;                             \
  (aElem)[1] = (aElem)[1] >> 1 | (aElem)[2] << 31;                             \
  (aElem)[2] = (aElem)[2] >> 1 | (aElem)[3] << 31;                             \
  (aElem)[3] = (aElem)[3] >> 1 | (aElem)[4] << 31;                             \
  (aElem)[4] = (aElem)[4] >> 1 | (aElem)[5] << 31;                             \
  (aElem)[5] = (aElem)[5] >> 1 | (aElem)[6] << 31;                             \
  (aElem)[6] = (aElem)[6] >> 1 | (aElem)[7] << 31;                             \
  (aElem)[7] = lastValue;

#define copy_eight(a, b)                                                       \
  (a)[0] = (b)[0], (a)[1] = (b)[1], (a)[2] = (b)[2], (a)[3] = (b)[3],          \
  (a)[4] = (b)[4], (a)[5] = (b)[5], (a)[6] = (b)[6], (a)[7] = (b)[7];

#define is_even(x) !((x)[0] & 1)

uint sub(uint *r, const uint *a, const uint *b) {
  uint c = 0;
  uint diff;

  diff = a[0] - b[0] - c;
  c = (diff != a[0]) ? (diff > a[0]) : c;
  r[0] = diff;
  diff = a[1] - b[1] - c;
  c = (diff != a[1]) ? (diff > a[1]) : c;
  r[1] = diff;
  diff = a[2] - b[2] - c;
  c = (diff != a[2]) ? (diff > a[2]) : c;
  r[2] = diff;
  diff = a[3] - b[3] - c;
  c = (diff != a[3]) ? (diff > a[3]) : c;
  r[3] = diff;
  diff = a[4] - b[4] - c;
  c = (diff != a[4]) ? (diff > a[4]) : c;
  r[4] = diff;
  diff = a[5] - b[5] - c;
  c = (diff != a[5]) ? (diff > a[5]) : c;
  r[5] = diff;
  diff = a[6] - b[6] - c;
  c = (diff != a[6]) ? (diff > a[6]) : c;
  r[6] = diff;
  diff = a[7] - b[7] - c;
  c = (diff != a[7]) ? (diff > a[7]) : c;
  r[7] = diff;
  return c;
}

uint add(uint *r, const uint *a, const uint *b) {
  uint c = 0, t;
  t = a[0] + b[0] + c;
  c = (t != a[0]) ? (t < a[0]) : c;
  r[0] = t;
  t = a[1] + b[1] + c;
  c = (t != a[1]) ? (t < a[1]) : c;
  r[1] = t;
  t = a[2] + b[2] + c;
  c = (t != a[2]) ? (t < a[2]) : c;
  r[2] = t;
  t = a[3] + b[3] + c;
  c = (t != a[3]) ? (t < a[3]) : c;
  r[3] = t;
  t = a[4] + b[4] + c;
  c = (t != a[4]) ? (t < a[4]) : c;
  r[4] = t;
  t = a[5] + b[5] + c;
  c = (t != a[5]) ? (t < a[5]) : c;
  r[5] = t;
  t = a[6] + b[6] + c;
  c = (t != a[6]) ? (t < a[6]) : c;
  r[6] = t;
  t = a[7] + b[7] + c;
  c = (t != a[7]) ? (t < a[7]) : c;
  r[7] = t;
  return c;
}

inline bool is_less(const uint *a, const uint *b) {
  for (int i = 7; i >= 0; i--) {
    if (a[i] < b[i])
      return true;
    if (a[i] > b[i])
      return false;
  }
  return false;
}
inline void shift_and_add(uint *x, uint *y, const uint *p) {
  shift_first(x, x[7] >> 1);
  uint c = 0;
  if (!is_even(y)) {
    c = add(y, y, p);
  }
  shift_first(y, y[7] >> 1 | c << 31);
}

inline void sub_and_shift(uint *x, const uint *y, uint *z, const uint *w,
                          const uint *p) {
  sub(x, x, y);
  shift_first(x, x[7] >> 1);
  if (is_less(z, w)) {
    add(z, z, p);
  }
  sub(z, z, w);

  if (!is_even(z)) {
    uint c = add(z, z, p);
    shift_first(z, z[7] >> 1 | c << 31);
  } else {
    shift_first(z, z[7] >> 1);
  }
}

inline bool is_greater(const uint *a, const uint *b) {
  for (int i = 7; i >= 0; i--) {
    if (a[i] != b[i])
      return (a[i] > b[i]);
  }
  return false;
}

inline bool arrays_equal(const uint *a, const uint *b) {
  for (int i = 0; i < 8; i++) {
    if (a[i] != b[i])
      return false;
  }
  return true;
}
inline void sub_mod(uint *r, const uint *a, const uint *b) {
  const uint c = sub(r, a, b);
  if (c) {
    uint t[8] = {SECPK256K_VALUES};
    add(r, r, t);
  }
}

inline void add_mod(uint *r, const uint *a, const uint *b) {
  uint t[8] = {SECPK256K_VALUES};
  if (!add(r, a, b)) {
    for (int i = 7; i >= 0; i--) {
      if (r[i] < t[i]) {
        return;
      }
      if (r[i] > t[i]) {
        break;
      }
    }
  }
  sub(r, r, t);
}

void mul_mod(uint *r, const uint *a, const uint *b) {
  uint t[16] = {0};
  uint t0 = 0;
  uint t1 = 0;
  uint c = 0;
  for (uint i = 0; i < 8; i++) {
    for (uint j = 0; j <= i; j++) {
      ulong p = ((ulong)a[j]) * b[i - j];
      ulong d = ((ulong)t1) << 32 | t0;

      d += p;
      t0 = (uint)d;
      t1 = d >> 32;
      c += d < p;
    }

    t[i] = t0;
    t0 = t1;
    t1 = c;
    c = 0;
  }

  for (uint i = 8; i < 15; i++) {
    for (uint j = i - 7; j < 8; j++) {
      ulong p = ((ulong)a[j]) * b[i - j];
      ulong d = ((ulong)t1) << 32 | t0;
      d += p;
      t0 = (uint)d;
      t1 = d >> 32;
      c += d < p;
    }
    t[i] = t0;
    t0 = t1;
    t1 = c;
    c = 0;
  }

  t[15] = t0;
  uint tmp[16] = {0};
  for (uint i = 0, j = 8; i < 8; i++, j++) {
    ulong p = ((ulong)0x03d1) * t[j] + c;
    tmp[i] = (uint)p;
    c = p >> 32;
  }
  tmp[8] = c;
  c = add(tmp + 1, tmp + 1, t + 8);
  tmp[9] = c;
  c = add(r, t, tmp);
  uint c2 = 0;
  for (uint i = 0, j = 8; i < 8; i++, j++) {
    ulong p = ((ulong)0x3d1) * tmp[j] + c2;
    t[i] = (uint)p;
    c2 = p >> 32;
  }

  t[8] = c2;
  c2 = add(t + 1, t + 1, tmp + 8);
  t[9] = c2;

  uint h[8] = {SECPK256K_VALUES};
  for (uint i = c + add(r, r, t); i > 0; i--) {
    sub(r, r, h);
  }
  for (int i = 7; i >= 0; i--) {
    if (r[i] < h[i])
      break;
    if (r[i] > h[i]) {
      sub(r, r, h);
      break;
    }
  }
}

void inv_mod(uint *a) {
  uint t0[8] = {a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]};
  uint p[8] = {SECPK256K_VALUES};
  uint t1[8] = {SECPK256K_VALUES};
  uint t2[8] = {0x00000001, 0, 0, 0, 0, 0, 0, 0};
  uint t3[8] = {0};

  while (!arrays_equal(t0, t1)) {
    if (is_even(t0)) {
      shift_and_add(t0, t2, p);
    } else if (is_even(t1)) {
      shift_and_add(t1, t3, p);
    } else {
      if (is_greater(t0, t1)) {
        sub_and_shift(t0, t1, t2, t3, p);
      } else {
        sub_and_shift(t1, t0, t3, t2, p);
      }
    }
  }
  copy_eight(a, t2);
}

void point_double(uint *x, uint *y, uint *z) {

  uint t1[8];
  uint t2[8];
  uint t3[8] = {z[0], z[1], z[2], z[3], z[4], z[5], z[6], z[7]};
  uint t4[8];
  uint t5[8];
  uint t6[8];
  copy_eight(t2, y);
  mul_mod(t4, x, x);
  mul_mod(t5, y, y);
  mul_mod(t3, y, z);
  mul_mod(t1, x, t5);
  mul_mod(t5, t5, t5);
  add_mod(t2, t4, t4);
  add_mod(t4, t4, t2);
  uint c = 0;
  if (t4[0] & 1) {
    uint t[8] = {SECPK256K_VALUES};
    c = add(t4, t4, t);
  }
  shift_first(t4, t4[7] >> 1 | c << 31);
  mul_mod(t6, t4, t4);
  add_mod(t2, t1, t1);
  sub_mod(t6, t6, t2);
  sub_mod(t1, t1, t6);
  mul_mod(t4, t4, t1);
  sub_mod(t1, t4, t5);

  copy_eight(x, t6);
  copy_eight(y, t1);
  copy_eight(z, t3);
}

void point_add(uint *x1, uint *y1, uint *z1, __constant uint *x2,
               __constant uint *y2) // z2 = 1
{

  uint t1[8];
  uint t2[8];
  uint t3[8];
  uint t4[8];
  uint t5[8];
  uint t6[8];
  uint t7[8];
  uint t8[8];
  uint t9[8];

  copy_eight(t1, x1);
  copy_eight(t2, y1);
  copy_eight(t3, z1);
  copy_eight(t4, x2);
  copy_eight(t5, y2);

  mul_mod(t6, t3, t3); // t6 = t3^2

  mul_mod(t7, t6, t3); // t7 = t6*t3
  mul_mod(t6, t6, t4); // t6 = t6*t4
  mul_mod(t7, t7, t5); // t7 = t7*t5

  sub_mod(t6, t6, t1); // t6 = t6-t1
  sub_mod(t7, t7, t2); // t7 = t7-t2

  mul_mod(t8, t3, t6); // t8 = t3*t6
  mul_mod(t4, t6, t6); // t4 = t6^2
  mul_mod(t9, t4, t6); // t9 = t4*t6
  mul_mod(t4, t4, t1); // t4 = t4*t1

  t6[7] = t4[7] << 1 | t4[6] >> 31;
  t6[6] = t4[6] << 1 | t4[5] >> 31;
  t6[5] = t4[5] << 1 | t4[4] >> 31;
  t6[4] = t4[4] << 1 | t4[3] >> 31;
  t6[3] = t4[3] << 1 | t4[2] >> 31;
  t6[2] = t4[2] << 1 | t4[1] >> 31;
  t6[1] = t4[1] << 1 | t4[0] >> 31;
  t6[0] = t4[0] << 1;

  if (t4[7] & 0x80000000) {
    uint a[8] = {0x000003d1, 1, 0, 0, 0, 0, 0, 0};
    add(t6, t6, a);
  }

  mul_mod(t5, t7, t7); // t5 = t7*t7
  sub_mod(t5, t5, t6); // t5 = t5-t6
  sub_mod(t5, t5, t9); // t5 = t5-t9
  sub_mod(t4, t4, t5); // t4 = t4-t5
  mul_mod(t4, t4, t7); // t4 = t4*t7
  mul_mod(t9, t9, t2); // t9 = t9*t2
  sub_mod(t9, t4, t9); // t9 = t4-t9

  copy_eight(x1, t5);
  copy_eight(y1, t9);
  copy_eight(z1, t8);
}

uint msb_point(uint *n) {
  uint msb = 256;
  for (int i = 8; i >= 0; i--) {
    if (n[i]) {
      msb = i * 32 + 31 - __builtin_clz(n[i]);
      break;
    }
  }
  return msb;
}
int convert_to_window_naf(uint *naf, const uint *k) {
  int loop_start = 0;
  uint n[9] = {0, k[7], k[6], k[5], k[4], k[3], k[2], k[1], k[0]};

  // Encontre o MSB do número (último bit relevante)
  uint msb = msb_point(n);

  for (int i = 0; i <= msb; i++) {
    if (n[8] & 1) {
      int diff = n[8] & 0x0f;
      int val = diff;

      if (diff >= 0x08) {
        diff -= 0x10;
        val = 0x11 - val;
      }

      naf[i >> 3] |= val << ((i & 7) << 2);

      uint t = n[8];
      n[8] -= diff;

      uint k = 8;

      while (k > 0 && ((diff > 0 && n[k] > t) || (diff < 0 && t > n[k]))) {
        k--;
        t = n[k];
        n[k] += (diff > 0) ? -1 : 1;
      }

      loop_start = i;
    }

    for (int j = 8; j > 0; j--) {
      n[j] = (n[j] >> 1) | (n[j - 1] << 31);
    }

    n[0] >>= 1;

    if (is_zero(n)) {
      break;
    }
  }

  return loop_start;
}

void point_mul_xy(uint *x1, uint *y1, const uint *k) {
  uint naf[SECP256K1_NAF_SIZE] = {0};
  int loop_start = convert_to_window_naf(naf, k);
  const uint multiplier =
      (naf[loop_start >> 3] >> ((loop_start & 7) << 2)) & 0x0f;

  const uint odd = multiplier & 1;

  const uint x_pos = ((multiplier - 1 + odd) >> 1) * 24;
  const uint y_pos = odd ? (x_pos + 8) : (x_pos + 16);

  copy_eight(x1, secpk256PreComputed + x_pos);
  copy_eight(y1, secpk256PreComputed + y_pos);
  uint z1[8] = {1, 0, 0, 0, 0, 0, 0, 0};

  for (int pos = loop_start - 1; pos >= 0; pos--) {
    point_double(x1, y1, z1);
    const uint multiplier = (naf[pos >> 3] >> ((pos & 7) << 2)) & 0x0f;

    if (multiplier) {
      const uint odd = multiplier & 1;
      const uint x_pos = ((multiplier - 1 + odd) >> 1) * 24;
      const uint y_pos = odd ? (x_pos + 8) : (x_pos + 16);
      point_add(x1, y1, z1, secpk256PreComputed + x_pos,
                secpk256PreComputed + y_pos);
    }
  }
  inv_mod(z1);
  uint z2[8];
  mul_mod(z2, z1, z1);
  mul_mod(x1, x1, z2);
  mul_mod(z1, z2, z1);
  mul_mod(y1, y1, z1);
}

#endif // EC_CL


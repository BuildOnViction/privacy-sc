import {EllipticCurve} from "./EllipticCurve.sol";
import "./SafeMath.sol";
/**
 * @title Secp256k1
 *
 * secp256k1 implementation.
 *
 * The library implements 'Curve' and 'codec/ECCConversion', but since it's a library
 * it does not actually extend the contracts. This is a Solidity thing and will be
 * dealt with later.
 *
 * @author Andreas Olofsson (androlo1980@gmail.com)
 */
library Secp256k1 {
    using SafeMath for uint256;

    // TODO separate curve from crypto primitives?
    uint256 constant n = 0x30644E72E131A029B85045B68181585D97816A916871CA8D3C208C16D87CFD47;
    // Field size
    uint constant pp = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;

    // Base point (generator) G
    uint constant Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint constant Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;

    uint constant Hx = 0x50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0;
    uint constant Hy = 0x31d3c6863973926e049e637cb1b5f40a36dac28af1766968c30c2313f3a38904;
    uint256 constant AA = 0;
    uint256 constant BB = 7;

    // Order of G
    uint constant nn = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    // Cofactor
    // uint constant hh = 1;

    // Maximum value of s
    uint constant lowSmax = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    // For later
    // uint constant lambda = "0x5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72";
    // uint constant beta = "0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee";

    /// @dev See Curve.onCurve
    function onCurve(uint[2] memory P) internal pure returns (bool) {
        uint p = pp;
        if (0 == P[0] || P[0] == p || 0 == P[1] || P[1] == p)
            return false;
        uint LHS = mulmod(P[1], P[1], p);
        uint RHS = addmod(mulmod(mulmod(P[0], P[0], p), P[0], p), 7, p);
        return LHS == RHS;
    }

    function onCurveXY(uint X, uint Y) internal pure returns (bool) {
        uint[2] memory P;
        P[0] = X;
        P[1] = Y;
        return onCurve(P);
    }

    function onCurveCompress(uint8 yBit, uint x) internal pure returns(bool) {
        uint[2] memory _decompressed = decompress(yBit, x);
        (uint8 _yBit, uint _x) = compress(_decompressed);
        return (_yBit == yBit && _x == x);
    }

    /// @dev See Curve.isPubKey
    function isPubKey(uint[2] memory P) internal pure returns (bool isPK) {
        isPK = onCurve(P);
    }

    /// @dev See Curve.validateSignature
    function validateSignature(uint message, uint[2] memory rs, uint[2] memory Q) internal pure returns (bool) {
        uint p = pp;
        if(rs[0] == 0 || rs[0] >= n || rs[1] == 0 || rs[1] > lowSmax)
            return false;
        if (!isPubKey(Q))
            return false;

        uint sInv = EllipticCurve.invMod(rs[1], p);
        uint[3] memory u1G = _mul(mulmod(message, sInv, n), [Gx, Gy]);
        uint[3] memory u2Q = _mul(mulmod(rs[0], sInv, n), Q);
        uint[3] memory P;
        (P[0], P[1], P[2]) = EllipticCurve.jacAdd(u1G[0], u1G[1], u1G[2], u2Q[0], u2Q[1], u2Q[2], pp);
        if (P[2] == 0)
            return false;

        uint Px = EllipticCurve.invMod(P[2], p); // need Px/Pz^2
        Px = mulmod(P[0], mulmod(Px, Px, p), p);
        return Px % n == rs[0];
    }

    function pedersenCommitment(uint256 mask, uint256 val) internal pure returns(uint8 yBit, uint x) {
        (uint256 tempX, uint256 tempY) = EllipticCurve.ecMul(
            mask,
            Gx,
            Gy,
            AA,
            pp
        );
        (uint256 valx, uint256 valy) = EllipticCurve.ecMul(
            val,
            Hx,
            Hy,
            AA,
            pp
        );
        (uint256 qx, uint256 qy) = EllipticCurve.ecAdd(
            tempX, tempY,
            valx, valy,
            AA, pp
        );
        (yBit, x) = compressXY(qx, qy);
    }

    function mulWithH(uint256 privKey) internal pure returns(uint8 yBit, uint x) {
        (uint256 qx, uint256 qy) = EllipticCurve.ecMul(
            privKey,
            Hx,
            Hy,
            AA,
            pp
        );
        (yBit, x) = compressXY(qx, qy);
    }

    /// @dev See Curve.compress
    function compress(uint[2] memory P) internal pure returns (uint8 yBit, uint x) {
        assert(P.length == 2);
        (yBit, x) = compressXY(P[0], P[1]);
    }

    function compressXY(uint _x, uint _y) internal pure returns (uint8 yBit, uint x) {
        x = _x;
        if ((_y.add(uint256(0))) % 2 == 0)
            yBit = 0;
        else yBit = 1;
    }

    /// @dev See Curve.decompress
    function decompress(uint8 yBit, uint x) internal pure returns (uint[2] memory P) {
        uint p = pp;
        uint y2 = addmod(mulmod(x, mulmod(x, x, p), p), 7, p);
        uint y_ = EllipticCurve.expMod(y2, (p + 1) / 4, p);
        uint cmp = yBit ^ y_ & 1;
        P[0] = x;
        P[1] = (cmp == 0) ? y_ : p - y_;
    }

    /// @dev See Curve.decompress
    function decompressXY(uint8 yBit, uint x) internal pure returns (uint X, uint Y) {
        uint p = pp;
        uint y2 = addmod(mulmod(x, mulmod(x, x, p), p), 7, p);
        uint y_ = EllipticCurve.expMod(y2, (p + 1) / 4, p);
        uint cmp = yBit ^ y_ & 1;
        X = x;
        Y = (cmp == 0) ? y_ : p - y_;
    }

    // Returns the inverse in the field of modulo n
    function inverse(uint256 num) internal pure
    returns(uint256 invNum)
    {
        uint256 t = 0;
        uint256 newT = 1;
        uint256 r = n;
        uint256 newR = num;
        uint256 q;
        while (newR != 0) {
            q = r / newR;

            (t, newT) = (newT, addmod(t, (n - mulmod(q, newT,n)), n));
            (r, newR) = (newR, r - q * newR );
        }

        invNum = t;
    }

    // Transform from projective to affine coordinates
    function toAffinePoint(uint256 x0, uint256 y0, uint256 z0) internal pure
    returns(uint256 x1, uint256 y1)
    {
        (x1, y1) = EllipticCurve.toAffine(x0, y0, z0, pp);
    }

    // Add two elliptic curve points (affine coordinates)
    function add(uint256 x0, uint256 y0,
        uint256 x1, uint256 y1) internal pure
    returns(uint256, uint256)
    {
        return EllipticCurve.ecAdd(x0, y0, x1, y1, AA, pp);
    }

    function sub(uint256 x0, uint256 y0,
        uint256 x1, uint256 y1) internal pure
    returns(uint256, uint256)
    {
        return EllipticCurve.ecSub(x0, y0, x1, y1, AA, pp);
    }

    // Multiplication dP. P affine, wNAF: w=5
    // Params: d, Px, Py
    // Output: Jacobian Q
    function _mul(uint d, uint[2] memory P) internal pure returns (uint[3] memory Q) {
        (Q[0], Q[1], Q[2]) = EllipticCurve.jacMul(
            d,
            P[0],
            P[1],
            1,
            AA,
            pp);
    }

}
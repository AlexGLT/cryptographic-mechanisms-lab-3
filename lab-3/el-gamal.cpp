#include "./el-gamal.hpp";


ElGamal::ElGamal(const uint64_t& keyLength)
{
    this->keyLength = keyLength;

    p = rand_prime_big_number(keyLength);

    q = (p - 1) / 2;

    g = BigNumber::sqr_mod(rand_big_number(keyLength - 1, -1), p);

    x = rand_big_number(keyLength - 2, 0);

    y = BigNumber::exp_mod(g, x, p);
}

std::pair<BigNumber, BigNumber> ElGamal::encrypt(const BigNumber& m)
{
    BigNumber k = rand_big_number(keyLength - 2, 0);

    auto c = std::pair<BigNumber, BigNumber>();

    c.first = BigNumber::exp_mod(g, k, p);
    c.second = (m * BigNumber::exp_mod(y, k, p)) % p;

    return c;
}

BigNumber ElGamal::decrypt(const std::pair<BigNumber, BigNumber>& c)
{
    return (c.second * BigNumber::exp_mod(c.first, -x % (p - 1), p)) % p;
}

std::pair<BigNumber, BigNumber> ElGamal::sign(const BigNumber& m)
{
    BigNumber k = rand_big_number(keyLength - 2, 0);

    auto sign = std::pair<BigNumber, BigNumber>();

    sign.first = BigNumber::exp_mod(g, k, p);
    sign.second = (m - sign.first * x) * BigNumber::exp_mod(k, q - 2, q) % q;

    return sign;
}

bool ElGamal::verify(const BigNumber& m, const std::pair<BigNumber, BigNumber>& sign)
{
    BigNumber leftPart = BigNumber::exp_mod(y, sign.first, p) * BigNumber::exp_mod(sign.first, sign.second, p) % p;
    BigNumber rightPart = BigNumber::exp_mod(g, m, p);

    return leftPart == rightPart;
}

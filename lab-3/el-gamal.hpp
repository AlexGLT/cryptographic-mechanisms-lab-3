#pragma once

#include "./big-number.hpp";


class ElGamal
{
public:
    uint64_t keyLength;

    BigNumber p;
    BigNumber q;
    BigNumber g;
    BigNumber x;
    BigNumber y;

    ElGamal(const uint64_t& keyLength = 2048);

    std::pair<BigNumber, BigNumber> encrypt(const BigNumber& m);
    BigNumber decrypt(const std::pair<BigNumber, BigNumber>& c);
    std::pair<BigNumber, BigNumber> sign(const BigNumber& m);
    bool verify(const BigNumber& m, const std::pair<BigNumber, BigNumber>& sign);
};
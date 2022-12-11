#pragma once

#include <iostream>;
#include <stdexcept>;
#include <sstream>;
#include <memory>;
#include <new>;
#include <vector>;
#include <string>;

#include "openssl/bn.h";
#include "openssl/err.h";


class BigNumber
{
    using bigNumberPointer = std::unique_ptr<BIGNUM, decltype(&::BN_free)>;
    using bigNumberContext = std::unique_ptr<BN_CTX, decltype(&::BN_CTX_free)>;

public:
    bigNumberPointer value;

    BigNumber();
    BigNumber(const int64_t number);
    BigNumber(const std::string& str);
    BigNumber(const BigNumber& obj);

    BigNumber& operator=(const BigNumber& obj);

    static BigNumber add(const BigNumber& firstOperand, const BigNumber& secondOperand);
    static BigNumber sub(const BigNumber& firstOperand, const BigNumber& secondOperand);
    static BigNumber mod(const BigNumber& number, const BigNumber& modulo);
    static BigNumber add_mod(const BigNumber& firstOperand, const BigNumber& secondOperand, const BigNumber& modulo);
    static BigNumber mul(const BigNumber& firstOperand, const BigNumber& secondOperand);
    static BigNumber mul_mod(const BigNumber& firstOperand, const BigNumber& secondOperand, const BigNumber& modulo);
    static BigNumber div(const BigNumber& firstOperand, const BigNumber& secondOperand);
    static BigNumber sqr_mod(const BigNumber& number, const BigNumber& modulo);
    static BigNumber exp_mod(const BigNumber& number, const BigNumber& power, const BigNumber& modulo);

    friend BigNumber rand_big_number(const uint64_t& bitsCount, const int8_t& firstSignificantBit);
    friend BigNumber rand_prime_big_number(const uint64_t& bitsCount, const int8_t& firstSignificantBit);

    friend std::ostream& operator<<(std::ostream& out, const BigNumber& number);

protected:
    static BIGNUM* initEmpty();
    static BIGNUM* initDecimal(const int64_t& number);
    static BIGNUM* initHex(const std::string& hexString);
    static BIGNUM* copy(const bigNumberPointer& arg);
};

BigNumber rand_big_number(const uint64_t& bitsCount, const int8_t& firstSignificantBit);
BigNumber rand_prime_big_number(const uint64_t& bitsCount);

BigNumber operator+(const BigNumber& firstOperand, const BigNumber& secondOperand);
BigNumber operator+(const int64_t& firstOperand, const BigNumber& secondOperand);
BigNumber operator+(const BigNumber& firstOperand, const int64_t& secondOperand);

BigNumber operator-(const BigNumber& number);
BigNumber operator-(const BigNumber& firstOperand, const BigNumber& secondOperand);
BigNumber operator-(const int64_t& firstOperand, const BigNumber& secondOperand);
BigNumber operator-(const BigNumber& firstOperand, const int64_t& secondOperand);

BigNumber operator*(const BigNumber& firstOperand, const BigNumber& secondOperand);
BigNumber operator*(const int64_t& firstOperand, const BigNumber& secondOperand);
BigNumber operator*(const BigNumber& firstOperand, const int64_t& secondOperand);

BigNumber operator/(const BigNumber& firstOperand, const BigNumber& secondOperand);
BigNumber operator/(const int64_t& firstOperand, const BigNumber& secondOperand);
BigNumber operator/(const BigNumber& firstOperand, const int64_t& secondOperand);

BigNumber operator%(const BigNumber& firstOperand, const BigNumber& secondOperand);
BigNumber operator%(const int64_t& firstOperand, const BigNumber& secondOperand);
BigNumber operator%(const BigNumber& firstOperand, const int64_t& secondOperand);


bool operator==(const BigNumber& firstOperand, const BigNumber& secondOperand);
bool operator<(const BigNumber& firstOperand, const BigNumber& secondOperand);
bool operator>(const BigNumber& firstOperand, const BigNumber& secondOperand);

std::ostream& operator<<(std::ostream& out, const BigNumber& number);

#include "./big-number.hpp";


BigNumber::BigNumber(): value(initEmpty(), ::BN_free) {}
BigNumber::BigNumber(const int64_t number): value(initDecimal(number), ::BN_free) {}
BigNumber::BigNumber(const std::string& str): value(initHex(str), ::BN_free) {}
BigNumber::BigNumber(const BigNumber& obj): value(copy(obj.value), ::BN_free) {}

BigNumber& BigNumber::operator=(const BigNumber& obj)
{
    if (this != &obj) value.reset(BN_dup(obj.value.get()));

    return *this;
}

BigNumber BigNumber::add(const BigNumber& firstOperand, const BigNumber& secondOperand)
{
    BigNumber result;

    BN_add(result.value.get(), firstOperand.value.get(), secondOperand.value.get());

    return result;
}

BigNumber BigNumber::sub(const BigNumber& firstOperand, const BigNumber& secondOperand)
{
    BigNumber result;

    BN_sub(result.value.get(), firstOperand.value.get(), secondOperand.value.get());

    return result;
}

BigNumber BigNumber::mod(const BigNumber& number, const BigNumber& modulo)
{
    BigNumber result;
    bigNumberContext ctx(BN_CTX_new(), ::BN_CTX_free);

    BN_nnmod(result.value.get(), number.value.get(), modulo.value.get(), ctx.get());

    return result;
}

BigNumber BigNumber::add_mod(const BigNumber& firstOperand, const BigNumber& secondOperand, const BigNumber& modulo)
{
    BigNumber result;
    bigNumberContext ctx(BN_CTX_new(), ::BN_CTX_free);

    BN_mod_add(result.value.get(), firstOperand.value.get(), secondOperand.value.get(), modulo.value.get(), ctx.get());

    return result;
}

BigNumber BigNumber::mul(const BigNumber& firstOperand, const BigNumber& secondOperand)
{
    BigNumber result;
    bigNumberContext ctx(BN_CTX_new(), ::BN_CTX_free);

    BN_mul(result.value.get(), firstOperand.value.get(), secondOperand.value.get(), ctx.get());

    return result;
}

BigNumber BigNumber::mul_mod(const BigNumber& firstOperand, const BigNumber& secondOperand, const BigNumber& modulo)
{
    BigNumber result;
    bigNumberContext ctx(BN_CTX_new(), ::BN_CTX_free);

    BN_mod_mul(result.value.get(), firstOperand.value.get(), secondOperand.value.get(), modulo.value.get(), ctx.get());

    return result;
}

BigNumber BigNumber::div(const BigNumber& firstOperand, const BigNumber& secondOperand)
{
    BigNumber result;
    bigNumberContext ctx(BN_CTX_new(), ::BN_CTX_free);

    BN_div(result.value.get(), nullptr, firstOperand.value.get(), secondOperand.value.get(), ctx.get());

    return result;
}

BigNumber BigNumber::sqr_mod(const BigNumber& number, const BigNumber& modulo)
{
    return BigNumber::mul_mod(number, number, modulo);
}

BigNumber BigNumber::exp_mod(const BigNumber& number, const BigNumber& power, const BigNumber& modulo)
{
    BigNumber result;
    bigNumberContext ctx(BN_CTX_new(), ::BN_CTX_free);

    BN_mod_exp(result.value.get(), number.value.get(), power.value.get(), modulo.value.get(), ctx.get());

    return result;
}

BIGNUM* BigNumber::initEmpty()
{
    auto bigNumber = BN_new();
    BN_zero(bigNumber);

    return bigNumber;
}

BIGNUM* BigNumber::initDecimal(const int64_t& number)
{
    auto bigNumber = BN_new();
    BN_dec2bn(&bigNumber, std::to_string(number).c_str());

    return bigNumber;
}

BIGNUM* BigNumber::initHex(const std::string& hexString)
{
    auto bigNumber = BN_new();
    BN_hex2bn(&bigNumber, hexString.c_str());

    return bigNumber;
}

BIGNUM* BigNumber::copy(const bigNumberPointer& arg)
{
    return BN_dup(arg.get());
}

BigNumber rand_big_number(const uint64_t& bitsCount, const int8_t& firstSignificantBit)
{
    BigNumber randomNumber;
    BN_rand(randomNumber.value.get(), bitsCount - 1, firstSignificantBit, false);

    return randomNumber;
}

BigNumber rand_prime_big_number(const uint64_t& bitsCount)
{
    BigNumber randomPrime;
    BN_generate_prime_ex(randomPrime.value.get(), bitsCount, 1, NULL, NULL, NULL);

    return randomPrime;
}

BigNumber operator+(const BigNumber& firstOperand, const BigNumber& secondOperand)
{
    return BigNumber::add(firstOperand, secondOperand);
}

BigNumber operator+(const int64_t& firstOperand, const BigNumber& secondOperand)
{
    return BigNumber::add(firstOperand, secondOperand);
}

BigNumber operator+(const BigNumber& firstOperand, const int64_t& secondOperand)
{
    return BigNumber::add(firstOperand, secondOperand);
}

BigNumber operator-(const BigNumber& number)
{
    return -1 * number;
}

BigNumber operator-(const BigNumber& firstOperand, const BigNumber& secondOperand)
{
    return BigNumber::sub(firstOperand, secondOperand);
}

BigNumber operator-(const int64_t& firstOperand, const BigNumber& secondOperand)
{
    return BigNumber::sub(firstOperand, secondOperand);
}

BigNumber operator-(const BigNumber& firstOperand, const int64_t& secondOperand)
{
    return BigNumber::sub(firstOperand, secondOperand);
}

BigNumber operator*(const BigNumber& firstOperand, const BigNumber& secondOperand)
{
    return BigNumber::mul(firstOperand, secondOperand);
}

BigNumber operator*(const int64_t& firstOperand, const BigNumber& secondOperand)
{
    return BigNumber::mul(firstOperand, secondOperand);
}

BigNumber operator*(const BigNumber& firstOperand, const int64_t& secondOperand)
{
    return BigNumber::mul(firstOperand, secondOperand);
}

BigNumber operator/(const BigNumber& firstOperand, const BigNumber& secondOperand)
{
    return BigNumber::div(firstOperand, secondOperand);
}

BigNumber operator/(const int64_t& firstOperand, const BigNumber& secondOperand)
{
    return BigNumber::div(firstOperand, secondOperand);
}

BigNumber operator/(const BigNumber& firstOperand, const int64_t& secondOperand)
{
    return BigNumber::div(firstOperand, secondOperand);
}

BigNumber operator%(const BigNumber& firstOperand, const BigNumber& secondOperand)
{
    return BigNumber::mod(firstOperand, secondOperand);
}

BigNumber operator%(const int64_t& firstOperand, const BigNumber& secondOperand)
{
    return BigNumber::mod(firstOperand, secondOperand);
}

BigNumber operator%(const BigNumber& firstOperand, const int64_t& secondOperand)
{
    return BigNumber::mod(firstOperand, secondOperand);
}

bool operator==(const BigNumber& firstOperand, const BigNumber& secondOperand)
{
    return BN_cmp(firstOperand.value.get(), secondOperand.value.get()) == 0;
}

bool operator<(const BigNumber& firstOperand, const BigNumber& secondOperand)
{
    return BN_cmp(firstOperand.value.get(), secondOperand.value.get()) == -1;
}

bool operator>(const BigNumber& firstOperand, const BigNumber& secondOperand)
{
    return BN_cmp(firstOperand.value.get(), secondOperand.value.get()) == 1;
}

std::ostream& operator<<(std::ostream& out, const BigNumber& number)
{
    const long f = out.flags() & std::ios::basefield;
    char* ptr = nullptr;

    ptr = BN_bn2hex(number.value.get());
    out << ptr;

    return out;
}

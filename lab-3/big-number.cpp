#include "big-number.hpp";


class BigNumber
{
    using bigNumberPointer = std::unique_ptr<BIGNUM, decltype(&::BN_free)>;
    using bigNumberContext = std::unique_ptr<BN_CTX, decltype(&::BN_CTX_free)>;
    using bigNumberMontgomeryContext = std::unique_ptr<BN_MONT_CTX, decltype(&::BN_MONT_CTX_free)>;

private:
    bigNumberPointer value;

public:
    BigNumber(): value(init(), ::BN_free) {}
    BigNumber(const std::string &str): value(convertStringToBigNumber(str), ::BN_free) {}
    BigNumber(const BigNumber& obj): value(copy(obj.value), ::BN_free) {}

    BigNumber& operator=(const BigNumber& obj)
    {
        if (this != &obj)
            value.reset(BN_dup(obj.value.get()));

        return *this;
    }

    static BigNumber add(const BigNumber& firstOperand, const BigNumber& secondOperand)
    {
        BigNumber result;

        BN_add(result.value.get(), firstOperand.value.get(), secondOperand.value.get());

        return result;
    }

    static BigNumber sub(const BigNumber& firstOperand, const BigNumber& secondOperand)
    {
        BigNumber result;

        BN_sub(result.value.get(), firstOperand.value.get(), secondOperand.value.get());

        return result;
    }

    static BigNumber mod(const BigNumber& number, const BigNumber& modulo)
    {
        BigNumber result;
        bigNumberContext ctx(BN_CTX_new(), ::BN_CTX_free);

        BN_mod(result.value.get(), number.value.get(), modulo.value.get(), ctx.get());

        return result;
    }

    static BigNumber add_mod(const BigNumber& firstOperand, const BigNumber& secondOperand, const BigNumber& modulo)
    {
        BigNumber result;
        bigNumberContext ctx(BN_CTX_new(), ::BN_CTX_free);

        BN_mod_add(result.value.get(), firstOperand.value.get(), secondOperand.value.get(), modulo.value.get(), ctx.get());

        return result;
    }

    static BigNumber mul(const BigNumber& firstOperand, const BigNumber& secondOperand)
    {
        BigNumber result;
        bigNumberContext ctx(BN_CTX_new(), ::BN_CTX_free);
        
        BN_mul(result.value.get(), firstOperand.value.get(), secondOperand.value.get(), ctx.get());

        return result;
    }

    static BigNumber mul_mod(const BigNumber& firstOperand, const BigNumber& secondOperand, const BigNumber& modulo)
    {
        BigNumber result;
        bigNumberContext ctx(BN_CTX_new(), ::BN_CTX_free);
        bigNumberMontgomeryContext montCtx(BN_MONT_CTX_new(), ::BN_MONT_CTX_free);

        BN_mod_mul_montgomery(result.value.get(), firstOperand.value.get(), secondOperand.value.get(), montCtx.get(), ctx.get());

        return result;
    }

    static BigNumber exp_mod(const BigNumber& number, const BigNumber& power, const BigNumber& modulo)
    {
        BigNumber result;
        bigNumberContext ctx(BN_CTX_new(), ::BN_CTX_free);
        bigNumberMontgomeryContext montCtx(BN_MONT_CTX_new(), ::BN_MONT_CTX_free);

        BN_mod_exp_mont(result.value.get(), number.value.get(), power.value.get(), modulo.value.get(), ctx.get(), montCtx.get());

        return result;
    }

    friend std::ostream& operator<<(std::ostream& out, const BigNumber& number);

protected:
    static BIGNUM* init()
    {
        BIGNUM* z = BN_new();
        BN_zero(z);
        
        return z;
    }

    static BIGNUM* convertStringToBigNumber(const std::string &hexString)
    {
        BIGNUM* t = BN_new();
        BN_hex2bn(&t, hexString.c_str());
        
        return t;
    }

    static BIGNUM* copy(const bigNumberPointer& arg)
    {
        return BN_dup(arg.get());
    }
};

BigNumber operator+(const BigNumber& firstOperand, const BigNumber& secondOperand)
{
    return BigNumber::add(firstOperand, secondOperand);
}

BigNumber operator-(const BigNumber& firstOperand, const BigNumber& secondOperand)
{
    return BigNumber::sub(firstOperand, secondOperand);
}

BigNumber operator*(const BigNumber& firstOperand, const BigNumber& secondOperand)
{
    return BigNumber::mul(firstOperand, secondOperand);
}

BigNumber operator%(const BigNumber& firstOperand, const BigNumber& secondOperand)
{
    return BigNumber::mod(firstOperand, secondOperand);
}

std::ostream& operator<<(std::ostream& out, const BigNumber& number)
{
    const long f = out.flags() & std::ios::basefield;
    char* ptr = nullptr;

    if (f == std::ios::hex)
    {
        ptr = BN_bn2hex(number.value.get());
        out << ptr;
    }
    else if (f == std::ios::dec)
    {
        ptr = BN_bn2dec(number.value.get());
        out << ptr;
    }
    else throw std::runtime_error("Not implemented");

    if (ptr) OPENSSL_free(ptr);

    return out;
}
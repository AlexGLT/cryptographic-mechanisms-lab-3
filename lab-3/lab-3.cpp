#include <iostream>;

#include "./el-gamal.hpp";


int main()
{
	auto elGamalInstance = ElGamal(2048);

	{
		// Encrypting

		std::string m;

		std::cout << "Input message that will be encrypted:" << std::endl;
		std::cin >> m;

		std::cout << std::endl;

		auto cipherText = elGamalInstance.encrypt(m);

		std::cout << "c1:\n" << cipherText.first << std::endl;
		std::cout << "c2:\n" << cipherText.second << std::endl;

		std::cout << "-------------------------------" << std::endl;
	}

	// Decrypting

	{
		std::string c1, c2;

		std::cout << "Input message that will be decrypted:" << std::endl;
		std::cout << "c1: ";
		std::cin >> c1;

		std::cout << "c2: ";
		std::cin >> c2;

		std::cout << std::endl;

		std::cout << "m: \n" << elGamalInstance.decrypt(std::pair<BigNumber, BigNumber>(c1, c2)) << std::endl;

		std::cout << "-------------------------------" << std::endl;
	}

	// Signing

	{
		std::string m;

		std::cout << "Input message that will be signed:" << std::endl;
		std::cin >> m;

		std::cout << std::endl;

		auto sign = elGamalInstance.sign(m);

		std::cout << "r:\n" << sign.first << std::endl;
		std::cout << "s:\n" << sign.second << std::endl;

		std::cout << "-------------------------------" << std::endl;
	}

	// Verifying

	{
		std::string m, r, s;

		std::cout << "Input message and sign that will be verified:" << std::endl;
		std::cout << "m: ";
		std::cin >> m;

		std::cout << "r: ";
		std::cin >> r;

		std::cout << "s: ";
		std::cin >> s;

		std::cout << std::endl;

		auto verifyResult = elGamalInstance.verify(m, std::pair<BigNumber, BigNumber>(r, s));

		std::cout << "Sign is correct: " << verifyResult << std::endl;

		std::cout << "-------------------------------" << std::endl;
	}

	return 1;
}
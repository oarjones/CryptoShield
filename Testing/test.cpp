#include "pch.h"
#include "../CryptoShieldCore/Utils/StringUtils.h"


TEST(TestCaseName, TestName) {
  EXPECT_EQ(1, 1);
  EXPECT_TRUE(true);
}

// Nuevo test: Prueba una conversión básica de wstring a string (UTF-8)
TEST(StringUtilsTest, BasicWStringToStringConversion) {
    // Arrange
    std::wstring wide_string = L"Hola Mundo";
    std::string expected_string = "Hola Mundo";

    // Act
	std::string actual_string = CryptoShield::Utils::to_string_utf8(wide_string);

    // Assert
    ASSERT_EQ(expected_string, actual_string);
}

// Nuevo test: Prueba el manejo de una cadena vacía
TEST(StringUtilsTest, EmptyWStringToStringConversion) {
    // Arrange
    std::wstring wide_string = L"";
    std::string expected_string = "";

    // Act
    std::string actual_string = CryptoShield::Utils::to_string_utf8(wide_string); //

    // Assert
    ASSERT_EQ(expected_string, actual_string);
}
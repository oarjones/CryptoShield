#include "pch.h"  
#include "gtest/gtest.h"  

#include "../Service/CryptoShieldService/Detection/EntropyAnalyzer.h"

// 2. Escribe un test básico  
TEST(SetupVerificationTest, CanCreateDetectorComponent) {
	// Arrange & Act: Intenta crear un objeto de una de tus clases.  
	// Si esto compila, el enlazado de cabeceras funciona.  
	CryptoShield::Detection::ShannonEntropyAnalyzer analyzer;

	// Assert: Una simple comprobación para que el test sea válido.  
	ASSERT_TRUE(true);
}
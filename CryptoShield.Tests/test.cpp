#include "pch.h"  
#include "gtest/gtest.h"  

#include "../Service/CryptoShieldService/Detection/EntropyAnalyzer.h"

// 2. Escribe un test b�sico  
TEST(SetupVerificationTest, CanCreateDetectorComponent) {
	// Arrange & Act: Intenta crear un objeto de una de tus clases.  
	// Si esto compila, el enlazado de cabeceras funciona.  
	CryptoShield::Detection::ShannonEntropyAnalyzer analyzer;

	// Assert: Una simple comprobaci�n para que el test sea v�lido.  
	ASSERT_TRUE(true);
}
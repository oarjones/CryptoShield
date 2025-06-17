#pragma once

// --- Encabezados Est�ndar ---
// Definir WIN32_LEAN_AND_MEAN reduce el tama�o de las cabeceras de Windows
// y previene conflictos con otras librer�as.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

// Incluye otras librer�as est�ndar de C++ que usar�s frecuentemente en tus tests.
#include <vector>
#include <string>
#include <memory>
#include <stdexcept>
#include <filesystem>
#include <numeric>
#include <algorithm>
#include <random>
#include <set>


// --- Encabezado del Framework de Pruebas ---
#include "gtest/gtest.h"
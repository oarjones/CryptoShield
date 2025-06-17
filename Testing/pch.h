#pragma once

// --- Encabezados Estándar ---
// Definir WIN32_LEAN_AND_MEAN reduce el tamaño de las cabeceras de Windows
// y previene conflictos con otras librerías.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

// Incluye otras librerías estándar de C++ que usarás frecuentemente en tus tests.
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
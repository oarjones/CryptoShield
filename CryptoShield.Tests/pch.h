//
// pch.h
//

#pragma once

// --- INICIO DE LA MODIFICACI�N ---
// Incluir la cabecera principal de Windows primero para establecer el
// entorno de compilaci�n de modo usuario correctamente.
// Esto evita conflictos con las definiciones de tipos del sistema.
#include <windows.h>
#include <string.h> // Para memset y memcpy, que son la base de RtlZeroMemory/RtlCopyMemory
// --- FIN DE LA MODIFICACI�N ---

#include "gtest/gtest.h"
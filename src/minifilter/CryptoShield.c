#include <fltKernel.h>  // Incluye las definiciones necesarias para desarrollar filtros de sistema de archivos.
#include <dontuse.h>    // Evita el uso de funciones obsoletas o inseguras.

// Declaración del manejador del filtro. Este es un puntero a la estructura FLT_FILTER que representa nuestro filtro.
PFLT_FILTER FilterHandle = NULL;

// Función de callback que se ejecuta antes de que se complete una operación en un archivo.
FLT_PREOP_CALLBACK_STATUS
PreOperationCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,          // Datos de la operación que se está realizando.
    _In_ PCFLT_RELATED_OBJECTS FltObjects,    // Objetos relacionados con la operación (archivo, volumen, etc.).
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext  // Contexto de finalización (no lo usaremos aquí).
)
{
    // Verifica si la operación es una escritura en un archivo.
    if (Data->Iopb->MajorFunction == IRP_MJ_WRITE) {
        // Muestra un mensaje en el depurador con el nombre del archivo que se está modificando.
        DbgPrint("CryptoShield: Se detectó una operación de escritura en el archivo: %wZ\n", &FltObjects->FileObject->FileName);
    }

    // Indica que la operación puede continuar sin problemas.
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

// Función que se ejecuta cuando el driver se descarga (por ejemplo, al desinstalarlo).
VOID
DriverUnload(
    _In_ PDRIVER_OBJECT DriverObject  // Objeto que representa el driver.
)
{
    // Si el filtro está registrado, lo desregistra antes de descargar el driver.
    if (FilterHandle != NULL) {
        FltUnregisterFilter(FilterHandle);
    }
}

// Punto de entrada del driver. Esta función se ejecuta cuando el driver se carga en el sistema.
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,      // Objeto que representa el driver.
    _In_ PUNICODE_STRING RegistryPath      // Ruta del registro donde se almacena la configuración del driver.
)
{
    NTSTATUS status;  // Variable para almacenar el resultado de las operaciones.
    FLT_REGISTRATION FilterRegistration = {0};  // Estructura que define la configuración del filtro.

    // Configura la versión de la estructura FLT_REGISTRATION.
    FilterRegistration.Version = FLT_REGISTRATION_VERSION;

    // Especifica cuántas operaciones queremos interceptar.
    FilterRegistration.OperationRegistrationCount = 1;

    // Define las operaciones que queremos interceptar.
    FLT_OPERATION_REGISTRATION OperationRegistration[] = {
        { IRP_MJ_WRITE, 0, PreOperationCallback, NULL },  // Intercepta operaciones de escritura.
        { IRP_MJ_OPERATION_END }  // Marca el final de la lista de operaciones.
    };
    FilterRegistration.OperationRegistration = OperationRegistration;

    // Registra el filtro en el sistema.
    status = FltRegisterFilter(DriverObject, &FilterRegistration, &FilterHandle);
    if (!NT_SUCCESS(status)) {
        // Si el registro falla, devuelve el código de error.
        return status;
    }

    // Inicia el filtro para que comience a interceptar operaciones.
    status = FltStartFiltering(FilterHandle);
    if (!NT_SUCCESS(status)) {
        // Si no se puede iniciar el filtro, lo desregistra y devuelve el código de error.
        FltUnregisterFilter(FilterHandle);
        return status;
    }

    // Configura la función de descarga (DriverUnload) para que se llame cuando el driver se descargue.
    DriverObject->DriverUnload = DriverUnload;

    // Muestra un mensaje en el depurador indicando que el filtro está en ejecución.
    DbgPrint("CryptoShield: Filtro registrado y en ejecución.\n");

    // Devuelve un código de éxito para indicar que el driver se ha cargado correctamente.
    return STATUS_SUCCESS;
}
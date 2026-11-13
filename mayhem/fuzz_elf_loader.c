// Fuzzes the host-side SGX enclave ELF loader (oe_load_elf_enclave_image) and the image callbacks that
// consume its output (size, TLS, .oeinfo properties, relocation patching).
#include <openenclave/internal/load.h>
#include <openenclave/internal/properties.h>
#include <stdio.h>
#include <unistd.h>
#include "fuzz_common.h"
#include "../host/sgx/enclave.h"

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 64)
        return -1;

    const char* tmp = getenv("TMPDIR");
    char path[4096];
    snprintf(path, sizeof(path), "%s/oe_elf_XXXXXX", tmp && *tmp ? tmp : "/tmp");
    int fd = mkstemp(path);
    if (fd < 0)
        return -1;
    size_t off = 0;
    while (off < size)
    {
        ssize_t w = write(fd, data + off, size - off);
        if (w <= 0)
            break;
        off += (size_t)w;
    }
    close(fd);

    oe_enclave_image_t image;
    if (oe_load_elf_enclave_image(path, &image) == OE_OK)
    {
        size_t image_size = 0, tls_pages = 0;
        oe_sgx_enclave_properties_t props;
        (void)image.calculate_size(&image, &image_size);
        (void)image.get_tls_page_count(&image, &tls_pages);
        if (image.sgx_load_enclave_properties(&image, &props) == OE_OK)
            (void)image.sgx_update_enclave_properties(&image, &props);
        (void)image.sgx_patch(&image, image_size, 0);
        image.unload(&image);
    }
    unlink(path);
    return 0;
}

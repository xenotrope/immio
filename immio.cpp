/*
    Public domain.
    20260314
*/

#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>

#pragma comment(lib, "bcrypt.lib")

#define ID_BTN_SELECT_ISO 101
#define ID_BTN_VERIFY     102

#define READ_CHUNK_SIZE (1024 * 1024)   /* 1 MB read buffer */

HWND hBtnSelectISO, hBtnVerify;
char g_selectedFile[MAX_PATH] = {0};

/* ── Pre-approved ISO catalogue ─────────────────────────────────────────
   Add or remove entries here.  Each row is { display_filename, sha256_hex }.
   Hashes must be 64 lowercase hex characters.                            */
typedef struct { const char *sha256; const char *filename; } ISOEntry;

static const ISOEntry g_approvedISOs[] =
{
    { "f1e0469b220b318151bf5c9515380705ddc5d4f59dd0f1af6e78fea599f05e4a", "linuxmint-19.3-cinnamon-32bit.iso" },
    { "7a9e54212433c8547edfd789ac933c91a9bde1a61196fa7977c5357a2c40292d", "linuxmint-19.3-cinnamon-64bit.iso" },
    { "9d302939a07205383231c2e41f3712b2cea7f1bff0470eed2d16f6c6ef0abc0a", "linuxmint-19.3-mate-32bit.iso" },
    { "610385bd480d4f906774d865761c429bccc522cf9dd62a5928045fac8fa24bf6", "linuxmint-19.3-mate-64bit.iso" },
    { "9daafa1d804fd34e5cd42dab919bbe43b7e94eefa2669398dc73b43c6616d206", "linuxmint-19.3-xfce-32bit.iso" },
    { "30c509d062da0f754765b5ecba861486d1f3d6138fdcec6f70f5feb88b72e4ef", "linuxmint-19.3-xfce-64bit.iso" },

    { "2f6ae466ec9b7c6255e997b82f162ae88bfe640a8df16d3e2f495b6281120af9", "linuxmint-20-cinnamon-64bit.iso" },
    { "42fd764b3a3544a36d820f4164bb64aa5a6d982073e6d1afdea4853d3858fc98", "linuxmint-20-mate-64bit.iso" },
    { "761fb276da9746a068f4c8aa42e8d4981f352db92babe0ef8a08713eeb38246f", "linuxmint-20-xfce-64bit.iso" },

    { "966fead51235cb4f0cd023506d538df1eeecedf1b06971e12eac4b92c862fa2b", "linuxmint-20.1-cinnamon-64bit-edge.iso" },
    { "14f73c93f75e873f4ac70b6cddc83703755c2421135a8fbbfd6ccfeed107e971", "linuxmint-20.1-cinnamon-64bit.iso" },
    { "12ccfa2494acf761b2f5a3379ed770495d97051c3944571d5ad5e7c50d11c975", "linuxmint-20.1-mate-64bit.iso" },
    { "4f9cc6fa8a2d6fd7ffdf88478812ff994e36470ecfe50761f7efd56e6d3d7018", "linuxmint-20.1-xfce-64bit.iso" },

    { "034a6eb5e023526014d1b3d86e41ba19bc902a45060862353e7fe3311a8208a0", "linuxmint-20.2-cinnamon-64bit-edge.iso" },
    { "50b833f1f093c029bfb7ba6148c9ce96619c01a83e92f35287983fbd62f26b01", "linuxmint-20.2-cinnamon-64bit.iso" },
    { "6b71cbac79931296550187b82021d459174d67ce509d1f2c07a867059d84f4f4", "linuxmint-20.2-mate-64bit.iso" },
    { "3ade2a59635a071c42e68721cbcd3a43b8e511b22a1c56b16b451448d440c613", "linuxmint-20.2-xfce-64bit.iso" },

    { "b6b4bbfafdacf9e00f4c674ba237193b40347140917946cff0ede3b10dc6ea55", "linuxmint-20.3-cinnamon-64bit-edge.iso" },
    { "e739317677c2261ae746eee5f1f0662aa319ad0eff260d4eb7055d7c79d10952", "linuxmint-20.3-cinnamon-64bit.iso" },
    { "27de0b1e6d743d0efc2c193ec88d56a49941ce3e7d58b03730a4bb1895c25be5", "linuxmint-20.3-mate-64bit.iso" },
    { "4d37e6a57513d2cdb4a8a993f48a54b18e0d41e86b651326f1101c34460c4719", "linuxmint-20.3-xfce-64bit.iso" },

    { "f524114e4a10fb04ec428af5e8faf7998b18271ea72fbb4b63efe0338957c0f3", "linuxmint-21-cinnamon-64bit.iso" },
    { "02a80ca98f82838e14bb02753bd73ee0da996c9cda3f027ae1c0ffb4612c8133", "linuxmint-21-mate-64bit.iso" },
    { "3ad001dc15cb661c6652ce1d20ecdc85a939fa0b4b9325af5d0c65379cc3b17e", "linuxmint-21-xfce-64bit.iso" },

    { "2df322f030d8ff4633360930a92d78829d10e515d2f6975b9bdfd1c0de769aca", "linuxmint-21.1-cinnamon-64bit.iso" },
    { "f7fb9c0500e583c46587402578547ea56125e0a054097f9f464a2500830c8b25", "linuxmint-21.1-mate-64bit.iso" },
    { "6fea221b5b0272d55de57f3d31498cdf76682f414e60d28131dc428e719efa8b", "linuxmint-21.1-xfce-64bit.iso" },

    { "116578dda0e03f1421c214acdd66043b586e7afc7474e0796c150ac164a90a2a", "linuxmint-21.2-cinnamon-64bit.iso" },
    { "46b1e171d678d0eba7916ed2b4eecac8993c5e94d3d5a1231ca7d480314f1553", "linuxmint-21.2-mate-64bit.iso" },
    { "e532dca4f28a88e52587a0e1af14236b233d2cec629d9f93e7c92383b4490a55", "linuxmint-21.2-xfce-64bit.iso" },
    { "b149f7fc4cbbc9f8fb547d50fef3e761a9c918ded55e67c33214997f007b91bd", "linuxmint-21.2-cinnamon-64bit-edge.iso" },

    { "5aa24abbc616807ab754a6a3b586f24460b0c213b6cacb0bf8b9a80b65013ecc", "linuxmint-21.3-cinnamon-64bit.iso" },
    { "ac79f36b82896e74299fa6dd1f40f00648ca2160903fea5d4d138db99fc6ad4e", "linuxmint-21.3-cinnamon-64bit-edge.iso" },
    { "c7b0c703476fcf7cfcfc66974b60984f35479fe1f2f054b00bc3c4cb97f37687", "linuxmint-21.3-mate-64bit.iso" },
    { "b284afcc298cc6f5da6ab4d483318c453b2074485974b71b16fdfc7256527cb1", "linuxmint-21.3-xfce-64bit.iso" },

    { "7a04b54830004e945c1eda6ed6ec8c57ff4b249de4b331bd021a849694f29b8f", "linuxmint-22-cinnamon-64bit.iso" },
    { "78a2438346cfe69a1779b0ac3fc05499f8dc7202959d597dd724a07475bc6930", "linuxmint-22-mate-64bit.iso" },
    { "55e917b99206187564029476f421b98f5a8a0b6e54c49ff6a4cb39dcfeb4bd80", "linuxmint-22-xfce-64bit.iso" },

    { "ccf482436df954c0ad6d41123a49fde79352ca71f7a684a97d5e0a0c39d7f39f", "linuxmint-22.1-cinnamon-64bit.iso" },
    { "d286306d0f40bd7268f08c523ece5fba87c0369a27a72465a19447e3606c5fa0", "linuxmint-22.1-mate-64bit.iso" },
    { "6451496af35e6855ffe1454f061993ea9cb884d2b4bc8bf17e7d5925ae2ae86d", "linuxmint-22.1-xfce-64bit.iso" },

    { "759c9b5a2ad26eb9844b24f7da1696c705ff5fe07924a749f385f435176c2306", "linuxmint-22.2-cinnamon-64bit.iso" },
    { "21f5a5f7be652c60b20ba7996328098b14e979b1ef8bf7f6c9d4a2a579504a65", "linuxmint-22.2-mate-64bit.iso" },
    { "dea13e523dca28e3aa48d90167a6368c63e1b3251492115417fdbf648551558f", "linuxmint-22.2-xfce-64bit.iso" },

    { "a081ab202cfda17f6924128dbd2de8b63518ac0531bcfe3f1a1b88097c459bd4", "linuxmint-22.3-cinnamon-64bit.iso" },
    { "7609294da613b75eea89bb918292125e9f06418a368136fb190466e15bf8c373", "linuxmint-22.3-mate-64bit.iso" },
    { "45a835b5dddaf40e84d776549e0b19b3fbd49673b6cc6434ebddbfcd217df776", "linuxmint-22.3-xfce-64bit.iso" },

    { "e7583d7428a36b54986d4bf29ebcc000f6959ee701c2379ca214fac6b32fe479", "lmde-4-cinnamon-32bit.iso"},
    { "fb6fb4f507f1de979a8922f9e503ae0ad8109e87ea1a9a163a6b30f819971256", "lmde-4-cinnamon-64bit.iso"},
    { "1116d611be80ad496bdc5a7c0444f63564539891f2176f9b134ff9630c6b91c8", "lmde-5-cinnamon-32bit.iso"},
    { "8f351d30e97f3a9c3f3848fde781c7f3758abd0f8ddf120827d98a5832cfa027", "lmde-5-cinnamon-64bit.iso"},
    { "40a9988cc6edd253bff9fcab422aec1b2c81ab3aa4d34b91b08277592c5fab28", "lmde-6-cinnamon-32bit.iso"},
    { "96963cac1ac2ad4ba38414e618adbcdf64a6faadc33ddf53889fa3dc74d59df4", "lmde-6-cinnamon-64bit.iso"},
    { "520b9de3e06871d69292f0e82a5979b62088ad83fdf4dce1d19100118a7033e4", "lmde-7-cinnamon-64bit.iso"},

};

static const int g_approvedCount =
    (int)(sizeof(g_approvedISOs) / sizeof(g_approvedISOs[0]));

/*
 * ComputeSHA256 - reads the file at `path` in chunks and produces a
 * hex-encoded SHA-256 digest in `outHex` (must be at least 65 bytes).
 * Returns TRUE on success, FALSE on any error.
 */
static BOOL ComputeSHA256(HWND hwnd, const char *path, char *outHex)
{
    BOOL success = FALSE;

    BCRYPT_ALG_HANDLE  hAlg  = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    PBYTE  pbHashObject      = NULL;
    PBYTE  pbHash            = NULL;
    PBYTE  pbBuffer          = NULL;
    DWORD  cbHashObject      = 0;
    DWORD cbHash             = 0;
    DWORD cbData             = 0;
    HANDLE hFile             = INVALID_HANDLE_VALUE;

    /* ── Open the CNG SHA-256 provider ─────────────────────────────── */
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(
            &hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0)))
    {
        MessageBox(hwnd, "Failed to open BCrypt SHA-256 provider.",
                   "Error", MB_OK | MB_ICONERROR);
        goto cleanup;
    }

    /* ── Allocate the internal hash object ──────────────────────────── */
    if (!BCRYPT_SUCCESS(BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
            (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0)))
        goto cleanup;

    pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject);
    if (!pbHashObject) goto cleanup;

    /* ── Allocate the output digest buffer ──────────────────────────── */
    if (!BCRYPT_SUCCESS(BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH,
            (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0)))
        goto cleanup;

    pbHash = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHash);
    if (!pbHash) goto cleanup;

    /* ── Create the hash state ───────────────────────────────────────── */
    if (!BCRYPT_SUCCESS(BCryptCreateHash(
            hAlg, &hHash, pbHashObject, cbHashObject, NULL, 0, 0)))
        goto cleanup;

    /* ── Open the file ───────────────────────────────────────────────── */
    hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        MessageBox(hwnd, "Could not open the selected file.",
                   "Error", MB_OK | MB_ICONERROR);
        goto cleanup;
    }

    /* ── Feed file data to the hash in 1 MB chunks ───────────────────── */
    pbBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, READ_CHUNK_SIZE);
    if (!pbBuffer) goto cleanup;

    for (;;)
    {
        DWORD dwRead = 0;
        if (!ReadFile(hFile, pbBuffer, READ_CHUNK_SIZE, &dwRead, NULL))
        {
            MessageBox(hwnd, "Error reading file during hashing.",
                       "Error", MB_OK | MB_ICONERROR);
            goto cleanup;
        }
        if (dwRead == 0) break;  /* EOF */

        if (!BCRYPT_SUCCESS(BCryptHashData(hHash, pbBuffer, dwRead, 0)))
            goto cleanup;
    }

    /* ── Finalise and retrieve digest ───────────────────────────────── */
    if (!BCRYPT_SUCCESS(BCryptFinishHash(hHash, pbHash, cbHash, 0)))
        goto cleanup;

    /* ── Convert raw bytes to lowercase hex string ───────────────────── */
    for (DWORD i = 0; i < cbHash; i++)
        sprintf(outHex + i * 2, "%02x", pbHash[i]);
    outHex[cbHash * 2] = '\0';

    success = TRUE;

cleanup:
    if (pbBuffer)     HeapFree(GetProcessHeap(), 0, pbBuffer);
    if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
    if (hHash)        BCryptDestroyHash(hHash);
    if (pbHashObject) HeapFree(GetProcessHeap(), 0, pbHashObject);
    if (pbHash)       HeapFree(GetProcessHeap(), 0, pbHash);
    if (hAlg)         BCryptCloseAlgorithmProvider(hAlg, 0);

    return success;
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
    case WM_CREATE:
        hBtnSelectISO = CreateWindow(
            "BUTTON", "Select ISO",
            WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
            20, 20, 120, 30,
            hwnd, (HMENU)ID_BTN_SELECT_ISO,
            ((LPCREATESTRUCT)lParam)->hInstance, NULL);

        hBtnVerify = CreateWindow(
            "BUTTON", "Verify",
            WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
            160, 20, 120, 30,
            hwnd, (HMENU)ID_BTN_VERIFY,
            ((LPCREATESTRUCT)lParam)->hInstance, NULL);
        break;

    case WM_COMMAND:
        switch (LOWORD(wParam))
        {
        case ID_BTN_SELECT_ISO:
        {
            OPENFILENAME ofn = {0};
            char szFile[MAX_PATH] = {0};

            ofn.lStructSize  = sizeof(ofn);
            ofn.hwndOwner    = hwnd;
            ofn.lpstrFile    = szFile;
            ofn.nMaxFile     = sizeof(szFile);
            ofn.lpstrFilter  = "ISO Files\0*.iso\0All Files\0*.*\0";
            ofn.nFilterIndex = 1;
            ofn.lpstrTitle   = "Select an ISO File";
            ofn.Flags        = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

            if (GetOpenFileName(&ofn))
            {
                strncpy(g_selectedFile, szFile, MAX_PATH - 1);
            }
            break;
        }

        case ID_BTN_VERIFY:
        {
            if (g_selectedFile[0] == '\0')
            {
                MessageBox(hwnd,
                           "No ISO file selected. Please click \"Select ISO\" first.",
                           "Verify", MB_OK | MB_ICONWARNING);
                break;
            }

            /* SHA-256 hex digest is 64 chars + null terminator */
            char hexDigest[65] = {0};

            /* Disable both buttons while hashing */
            EnableWindow(hBtnSelectISO, FALSE);
            EnableWindow(hBtnVerify,    FALSE);
            SetWindowText(hBtnVerify, "Working...");

            BOOL ok = ComputeSHA256(hwnd, g_selectedFile, hexDigest);

            EnableWindow(hBtnSelectISO, TRUE);
            EnableWindow(hBtnVerify,    TRUE);
            SetWindowText(hBtnVerify, "Verify");

            if (!ok) break;

            /* ── Compare against pre-approved catalogue ─────────────── */
            const char *matchedName = NULL;
            for (int i = 0; i < g_approvedCount; i++)
            {
                if (_stricmp(hexDigest, g_approvedISOs[i].sha256) == 0)
                {
                    matchedName = g_approvedISOs[i].filename;
                    break;
                }
            }

            char resultMsg[MAX_PATH + 256];
            if (matchedName)
            {
                snprintf(resultMsg, sizeof(resultMsg),
                         "Verification PASSED\r\n\r\n"
                         "The checksum matches the approved image:\r\n"
                         "  %s\r\n\r\n"
                         "SHA-256:\r\n  %s",
                         matchedName, hexDigest);
                MessageBox(hwnd, resultMsg, "Verification Passed",
                           MB_OK | MB_ICONINFORMATION);
            }
            else
            {
                snprintf(resultMsg, sizeof(resultMsg),
                         "Verification FAILED\r\n\r\n"
                         "The checksum does not match any approved image.\r\n\r\n"
                         "SHA-256:\r\n  %s",
                         hexDigest);
                MessageBox(hwnd, resultMsg, "Verification Failed",
                           MB_OK | MB_ICONERROR);
            }
            break;
        }
        }
        break;

    case WM_DESTROY:
        PostQuitMessage(0);
        break;

    default:
        return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    return 0;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow)
{
    const char CLASS_NAME[] = "IMMIOToolWindow";

    WNDCLASS wc      = {0};
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.hCursor       = LoadCursor(NULL, IDC_ARROW);

    RegisterClass(&wc);

    HWND hwnd = CreateWindow(
        CLASS_NAME, "IMMIO Tool",
        WS_OVERLAPPEDWINDOW & ~WS_THICKFRAME & ~WS_MAXIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT,
        320, 100,
        NULL, NULL, hInstance, NULL);

    if (!hwnd) return 0;

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG msg = {0};
    while (GetMessage(&msg, NULL, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return (int)msg.wParam;
}

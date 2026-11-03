#pragma once
#include <stdbool.h>

/*
 * Panel logo routes on the admin port (fork addition, subsys; Basic auth and
 * the X-ShadowSentry POST header already checked by admin_panel.c):
 *
 *   GET  /api/ui/logo    the PNG the panel uses from the next boot: the card's
 *                        /sd/ui/logo.png when it is there and checks out, else
 *                        the built-in one. image/png, with X-Logo-Source:
 *                        card or built-in.
 *   POST /api/ui/logo    a PNG as the body, at most UI_LOGO_MAX_BYTES (200 KB),
 *                        at most UI_LOGO_MAX_PX (240) a side. Received into
 *                        PSRAM, signature and IHDR checked, then handed to
 *                        sd_log's writer, which writes /sd/ui/logo.png.tmp and
 *                        renames it. The panel decodes it at the next boot.
 *                        200 {"ok":true,"width","height","size"}; 400 not a PNG
 *                        or too large in pixels, 411 no length, 413 over 200 KB,
 *                        503 no card or no memory.
 *
 * Returns true when the request was one of these routes and has been answered.
 */
bool api_logo_handle(int sock, const char *req, int req_len);

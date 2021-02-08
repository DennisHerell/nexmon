/***************************************************************************
 *                                                                         *
 *          ###########   ###########   ##########    ##########           *
 *         ############  ############  ############  ############          *
 *         ##            ##            ##   ##   ##  ##        ##          *
 *         ##            ##            ##   ##   ##  ##        ##          *
 *         ###########   ####  ######  ##   ##   ##  ##    ######          *
 *          ###########  ####  #       ##   ##   ##  ##    #    #          *
 *                   ##  ##    ######  ##   ##   ##  ##    #    #          *
 *                   ##  ##    #       ##   ##   ##  ##    #    #          *
 *         ############  ##### ######  ##   ##   ##  ##### ######          *
 *         ###########    ###########  ##   ##   ##   ##########           *
 *                                                                         *
 *            S E C U R E   M O B I L E   N E T W O R K I N G              *
 *                                                                         *
 * This file is part of NexMon.                                            *
 *                                                                         *
 * Copyright (c) 2016 NexMon Team                                          *
 *                                                                         *
 * NexMon is free software: you can redistribute it and/or modify          *
 * it under the terms of the GNU General Public License as published by    *
 * the Free Software Foundation, either version 3 of the License, or       *
 * (at your option) any later version.                                     *
 *                                                                         *
 * NexMon is distributed in the hope that it will be useful,               *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of          *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           *
 * GNU General Public License for more details.                            *
 *                                                                         *
 * You should have received a copy of the GNU General Public License       *
 * along with NexMon. If not, see <http://www.gnu.org/licenses/>.          *
 *                                                                         *
 **************************************************************************/

#pragma NEXMON targetregion "patch"

#include <firmware_version.h>   // definition of firmware version macros
#include <debug.h>              // contains macros to access the debug hardware
#include <wrapper.h>            // wrapper definitions for functions that already exist in the firmware
#include <structs.h>            // structures that are used by the code in the firmware
#include <helper.h>             // useful helper functions
#include <patcher.h>            // macros used to craete patches such as BLPatch, BPatch, ...
#include <rates.h>              // rates used to build the ratespec for frame injection
#include <nexioctls.h>          // ioctls added in the nexmon patch
#include <capabilities.h>       // capabilities included in a nexmon patch
#include <sendframe.h>          // sendframe functionality
#include <argprintf.h>

static char packet_bytes[] = {
0x88, 0x42, 0x2c, 0x00,
0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
0x20, 0x21, 0x00, 0x00,
0x46, 0x09, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00,
0x32, 0xf5, 0x22, 0xdf, 0xf1, 0xb2, 0xf5, 0x9b,
0x19, 0x20, 0x0e, 0x56, 0x9e, 0x27, 0xac, 0x7c,
0x6c, 0xb0, 0xca, 0x4b, 0x56, 0x10, 0x10, 0x51,
0x8e, 0xe2, 0x19, 0x75, 0x4f, 0x80, 0x44, 0x7d,
0x87, 0x73, 0xc1, 0x0e, 0x2f, 0xf5, 0x2e, 0x7c,
0xdc, 0x05, 0xba, 0x91, 0x3e, 0xe0, 0x94, 0xd3,
0x82, 0x2a, 0x25, 0x3c, 0xe1, 0xbb, 0xb4, 0xef,
0x83, 0x60, 0xef, 0x3e, 0xf0, 0x79
};

int 
wlc_ioctl_hook(struct wlc_info *wlc, int cmd, char *arg, int len, void *wlc_if)
{
    argprintf_init(arg, len);
    int ret = IOCTL_ERROR;

    switch (cmd) {
        case NEX_GET_CAPABILITIES:
            if (len == 4) {
                memcpy(arg, &capabilities, 4);
                ret = IOCTL_SUCCESS;
            }
            break;

        case NEX_WRITE_TO_CONSOLE:
            if (len > 0) {
                arg[len-1] = 0;
                printf("ioctl: %s\n", arg);
                ret = IOCTL_SUCCESS;
            }
            break;

        case 500: // dump wlif list
            {
                struct wlc_if *wlcif = wlc->wlcif_list;

                for (wlcif = wlc->wlcif_list;  wlcif != 0; wlcif = wlcif->next) {
                    char ifname[32];

                    strncpy(ifname, wlcif->wlif == 0 ? wlc->wl->dev->name : wlcif->wlif->dev->name, sizeof(ifname));
                    ifname[sizeof(ifname) - 1] = '\0';

                    argprintf(" \"%s\" 0x%p type=%02x index=%02x flags=%02x\n", ifname, wlcif, wlcif->type, wlcif->index, wlcif->flags);
		}

                ret = IOCTL_SUCCESS;
            }
            break;
        case 599:
            {
                // suppress scanning
                set_scansuppress(wlc, 1);
                // disable minimal power consumption
                set_mpc(wlc, 0);
                // get length of packet
                int len = sizeof(packet_bytes);
                // reserve a packet buffer with header space
                sk_buff *p = pkt_buf_get_skb(wlc->osh, len + 202);
                // pull header space
                char *packet_skb = (char *) skb_pull(p, 202);
                // copy packet bytes to buffer
                memcpy(packet_skb, &packet_bytes, len);
                // send packet with specific rate
                uint32 rate = RATES_BW_20MHZ | RATES_OVERRIDE_MODE | RATES_ENCODE_VHT | RATES_VHT_MCS(4) | RATES_VHT_NSS(1);
                sendframe(wlc, p, 1, rate);
                printf("Starting Stream...");
                ret = IOCTL_SUCCESS;
            break;
        }
        default:
            ret = wlc_ioctl(wlc, cmd, arg, len, wlc_if);
    }

    return ret;
}

__attribute__((at(0x4305c, "", CHIP_VER_BCM43430a1, FW_VER_7_45_41_46)))
GenericPatch4(wlc_ioctl_hook, wlc_ioctl_hook + 1);


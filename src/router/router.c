/*
 *  chirouter - A simple, testable IP router
 *
 *  This module contains the actual functionality of the router.
 *  When the router receives an Ethernet frame, it is handled by
 *  the chirouter_process_ethernet_frame() function.
 *
 */

/*
 * This project is based on the Simple Router assignment included in the
 * Mininet project (https://github.com/mininet/mininet/wiki/Simple-Router) which,
 * in turn, is based on a programming assignment developed at Stanford
 * (http://www.scs.stanford.edu/09au-cs144/lab/router.html)
 *
 * While most of the code for chirouter has been written from scratch, some
 * of the original Stanford code is still present in some places and, whenever
 * possible, we have tried to provide the exact attribution for such code.
 * Any omissions are not intentional and will be gladly corrected if
 * you contact us at borja@cs.uchicago.edu
 */

/*
 *  Copyright (c) 2016, The University of Chicago
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  - Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 *  - Neither the name of The University of Chicago nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdio.h>
#include <assert.h>

#include <string.h>
#include <stdlib.h>

#include "chirouter.h"
#include "pox.h"
#include "arp.h"
#include "utils.h"


/*
 * chirouter_process_ethernet_frame - Process a single inbound Ethernet frame
 *
 * This function will get called every time an Ethernet frame is received by
 * the router. The router uses a single thread to process inbound Ethernet
 * frames, so you can assume that chirouter_process_ethernet_frame is always
 * called sequentially (there will never be concurrent calls to this function).
 *
 * This function receives the router context and the inbound frame
 * (the ethernet_frame_t struct contains a pointer to the interface
 * where the frame was received). Take into account that the chirouter
 * code will free the frame after this function returns so, if you
 * need to persist a frame (e.g., because you're adding it to a list of
 * withheld frames in the pending ARP request list) you must make
 * a deep copy of the frame.
 *
 * ctx: Router context
 *
 * frame: Inbound Ethernet frame
 *
 * Returns: 0 on success, 1 if an error happens.
 */
int chirouter_process_ethernet_frame(chirouter_ctx_t *ctx, ethernet_frame_t *frame)
{
    /* Your code goes here */

    return 0;
}



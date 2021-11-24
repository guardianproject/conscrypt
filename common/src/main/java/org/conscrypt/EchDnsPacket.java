/*
 * Copyright (C) 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.conscrypt;

import org.conscrypt.com.android.net.module.util.DnsPacket;

import java.io.ByteArrayOutputStream;

public class EchDnsPacket extends DnsPacket {

    private static final String TAG = "EchDnsPacket";
    private static final boolean DBG = true;

    /**
     * Service Binding [draft-ietf-dnsop-svcb-https-00]
     */
    public static final int TYPE_SVCB = 64;

    /**
     * HTTPS Binding [draft-ietf-dnsop-svcb-https-00]
     */
    public static final int TYPE_HTTPS = 65;
    /**
     * One or more catenated binary ECHConfigs
     */
    public static int ECH_FMT_BIN = 1;
    /**
     * < presentation form of HTTPSSVC
     */
    public static int ECH_FMT_HTTPSSVC = 4;
    /**
     * < Max RR value size, as given to API
     */
    private static int ECH_MAX_RRVALUE_LEN = 2000;
    /**
     * < for a sanity check
     */
    private static int ECH_MAX_ECHCONFIG_LEN = ECH_MAX_RRVALUE_LEN;
    /**
     * < Max for an ECHConfig extension
     */
    private static int ECH_MAX_ECHCONFIGEXT_LEN = 100;
    /**
     * < just for a sanity check
     */
    private static int ECH_MIN_ECHCONFIG_LEN = 32;
    /**
     * the wire-format code for ECH within an SVCB or HTTPS RData
     */
    private static int ECH_PCODE_ECH = 0x0005;

    private final int mQueryType;

    public EchDnsPacket(byte[] data) throws ParseException {
        super(data);
        if ((mHeader.flags & (1 << 15)) == 0) {
            throw new IllegalArgumentException("Not an answer packet");
        }
        if (mHeader.getRecordCount(QDSECTION) == 0) {
            throw new IllegalArgumentException("No question found");
        }
        // Expect only one question in question section.
        mQueryType = mRecords[QDSECTION].get(0).nsType;
    }

    /**
     * Decode SVCB/HTTPS RR value provided as binary or ascii-hex.
     * <p>
     * The rrval may be the catenation of multiple encoded ECHConfigs.
     * We internally try decode and handle those and (later)
     * use whichever is relevant/best.
     * <p>
     * Note that we "succeed" even if there is no ECHConfigs in the input - some
     * callers might download the RR from DNS and pass it here without looking
     * inside, and there are valid uses of such RRs. The caller can check though
     * using the num_echs output.
     *
     * @param rrval is the binary encoded RData
     * @return is 1 for success, error otherwise
     */
    static byte[] getEchConfigListFromDnsRR(byte[] rrval) {
        int rv = 0;
        int pos = 0;
        int remaining = rrval.length;
        int plen = 0;
        boolean done = false;

        /*
         * skip 2 octet priority and TargetName as those are the
         * application's responsibility, not the library's
         */
        if (remaining <= 2) return null;
        pos += 2;
        remaining -= 2;
        pos++;
        int clen = byteToUnsignedInt(rrval[pos]);
        ByteArrayOutputStream thename = new ByteArrayOutputStream();
        if (clen == 0) {
            // special case - return "." as name
            thename.write('.');
            rv = 1;
        }
        while (clen != 0) {
            if (clen > remaining) {
                rv = 1;
                break;
            }
            for (int i = pos; i < clen; i++) {
                thename.write(byteToUnsignedInt(rrval[pos + i]));
            }
            thename.write('.');
            pos += clen;
            remaining -= clen + 1;
            clen = byteToUnsignedInt(rrval[pos]);
        }
        if (rv != 1) {
            return null;
        }

        int echStart = 0;
        while (!done && remaining >= 4) {
            int pcode = (rrval[pos] << 8) + rrval[pos + 1];
            pos += 2;
            plen = (rrval[pos] << 8) + rrval[pos + 1];
            pos += 2;
            remaining -= 4;
            if (pcode == ECH_PCODE_ECH) {
                echStart = pos;
                done = true;
            }
            if (plen != 0 && plen <= remaining) {
                pos += plen;
                remaining -= plen;
            }
        }
        if (!done) {
            return null;
        }
        if (plen <= 0) {
            return null;
        }
        byte[] ret = new byte[plen];
        System.arraycopy(rrval, echStart, ret, 0, plen);
        return ret;
    }

    public byte[] getEchConfigList() {
        byte[] results = null;
        if (mHeader.getRecordCount(ANSECTION) == 0) return results;

        for (final DnsRecord ansSec : mRecords[ANSECTION]) {
            // Only support SVCB and HTTPS since only they can have ECH Config Lists
            int nsType = ansSec.nsType;
            if (nsType != mQueryType || (nsType != TYPE_SVCB && nsType != TYPE_HTTPS)) {
                continue;
            }
            try {
                results = getEchConfigListFromDnsRR(ansSec.getRR());
            } catch (ArrayIndexOutOfBoundsException e) {
                // TODO fix the parsing code to not ever do this
            }
        }
        return results;
    }
}

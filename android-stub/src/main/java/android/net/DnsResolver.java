/*
 * Copyright 2016 The Android Open Source Project
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

package android.net;

import android.os.CancellationSignal;
import java.util.concurrent.Executor;

/**
 * Stub class for compiling unbundled.
 */
public class DnsResolver {

    public static final int CLASS_IN = 1;
    public static final int FLAG_EMPTY = 0;

    public static DnsResolver getInstance() {
        throw new UnsupportedOperationException("Stub!");
    }

    private DnsResolver() {
        throw new UnsupportedOperationException("Stub!");
    }

    public interface Callback<T> {
        void onAnswer(T answer, int rcode);

        void onError(DnsException error);
    }

    @SuppressWarnings("serial")
    public static class DnsException extends Exception {
        DnsException(int code, Throwable cause) {
            throw new UnsupportedOperationException("Stub!");
        }
    }

    public void rawQuery(Network network, String domain,
            int nsClass, int nsType, int flags,
            Executor executor,
            CancellationSignal cancellationSignal,
            Callback<? super byte[]> callback) {
            throw new UnsupportedOperationException("Stub!");
    }
}

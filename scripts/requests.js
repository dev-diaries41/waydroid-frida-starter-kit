if (Java.available) {
    Java.perform(function () {
        console.log("[*] Starting universal network interceptor...");

        // Function to intercept OkHttp requests
        function interceptOkHttp() {
            try {
                var OkHttpClient = Java.use('okhttp3.OkHttpClient');
                var RequestBody = Java.use('okhttp3.RequestBody');
                var MediaType = Java.use('okhttp3.MediaType');
                var Buffer = Java.use('okio.Buffer');

                OkHttpClient.newCall.overload('okhttp3.Request').implementation = function (request) {
                    var url = request.url().toString();
                    var method = request.method();
                    var headers = request.headers().toString();
                    var requestBody = "";

                    try {
                        var body = request.body();
                        if (body) {
                            var contentType = body.contentType();
                            var mediaType = contentType ? contentType.toString() : "unknown";

                            if (mediaType.startsWith("application/json") || mediaType.startsWith("application/x-www-form-urlencoded")) {
                                var buffer = Buffer.$new();
                                body.writeTo(buffer);
                                requestBody = buffer.readUtf8();
                            }
                        }
                    } catch (e) {
                        console.log("[!] Failed to read OkHttp request body: " + e);
                    }

                    send({ type: "OkHttp", url: url, method: method, headers: headers, body: requestBody });
                    return this.newCall(request);
                };
                console.log("[*] Hooked OkHttpClient.newCall()");
            } catch (e) {
                console.log("[!] OkHttp hook failed: " + e);
            }
        }

        // Function to intercept HttpURLConnection requests
        function interceptHttpURLConnection() {
            try {
                var HttpURLConnection = Java.use('java.net.HttpURLConnection');

                HttpURLConnection.connect.implementation = function () {
                    var url = this.getURL().toString();
                    var method = this.getRequestMethod();
                    var headers = this.getRequestProperties().toString();

                    send({ type: "HttpURLConnection", url: url, method: method, headers: headers });
                    console.log("[*] HttpURLConnection Request Sent: " + url);
                    this.connect();
                };
                console.log("[*] Hooked HttpURLConnection.connect()");
            } catch (e) {
                console.log("[!] HttpURLConnection hook failed: " + e);
            }
        }

        // Function to intercept Apache HttpClient requests
        function interceptHttpClient() {
            try {
                var HttpClient = Java.use('org.apache.http.impl.client.DefaultHttpClient');
                HttpClient.execute.overload('org.apache.http.client.methods.HttpUriRequest').implementation = function (request) {
                    var url = request.getURI().toString();
                    var method = request.getMethod();
                    var headers = request.getAllHeaders().toString();

                    send({ type: "HttpClient", url: url, method: method, headers: headers });
                    console.log("[*] Apache HttpClient Request Sent: " + url);
                    return this.execute(request);
                };
                console.log("[*] Hooked Apache HttpClient.execute()");
            } catch (e) {
                console.log("[!] Apache HttpClient hook failed: " + e);
            }
        }

        // Function to bypass SSL Pinning
        function bypassSSLPinning() {
            try {
                var SSLContext = Java.use('javax.net.ssl.SSLContext');
                var TrustManagerFactory = Java.use('javax.net.ssl.TrustManagerFactory');

                // Initialize TrustManagerFactory and TrustManagers
                var trustManagerFactory = TrustManagerFactory.getInstance("X509");
                trustManagerFactory.init(null);  // Use no key store
                var trustManagers = trustManagerFactory.getTrustManagers();

                SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function (keyManager, trustManager, secureRandom) {
                    console.log("[*] Bypassing SSL Pinning...");
                    this.init(keyManager, trustManagers, secureRandom);  // Override with our trust managers
                };

                console.log("[*] SSL Pinning successfully bypassed!");
            } catch (e) {
                console.log("[!] SSL Pinning bypass hook failed: " + e);
            }
        }
        

        // Call functions to set up interceptors
        interceptOkHttp();
        interceptHttpURLConnection();
        interceptHttpClient();
        bypassSSLPinning();

        console.log("[*] Universal network interceptor is active.");
    });
}
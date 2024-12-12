if (Java.available) {
    Java.perform(function () {
        // Hook into the OkHttpClient class
        var OkHttpClient = Java.use('okhttp3.OkHttpClient');
        
        // Intercept the newCall method to capture request URLs and body
        OkHttpClient.newCall.overload('okhttp3.Request').implementation = function (request) {
            var url = request.url().toString(); // Get the URL of the request
            var requestBody = {}
            var headers = request.headers().toString();

            // Check if the request has a body and log it
            var body = request.body();
            if (body != null) {
                var content = null;
                try {
                    // Use reflection to get the content of the request body
                    var buffer = Java.use('okio.Buffer').$new();
                    body.writeTo(buffer); // Write the body to the buffer

                    // Convert the buffer content to a string (if it's text)
                    content = buffer.readUtf8(); 
                    requestBody = content
                } catch (e) {
                    console.log('[OkHttp] Failed to read request body: ' + e);
                }
            } 

            var reqData = {
                "url": url,
                "body": requestBody,
                "headers": headers
            }

            send(reqData);

            // Call the original method to proceed with the request
            return this.newCall(request);
        };

        console.log('[*] Hooked OkHttpClient.newCall()');
    });
}